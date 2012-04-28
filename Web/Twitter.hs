-- |
-- Module: Web.Twitter
-- Description: OAuth Twitter bindings
-- License: MIT
-- Maintainer: Patrick Hurst <phurst@mit.edu>
-- Stability: experimental
-- Portability: portable
--
-- Twitter bindings that use OAuth instead of basic authentication.
-- Any function here that returns a value might also throw a NotFound, AccessForbidden, or OtherError
-- if Twitter gives it the appropriate error (HTTP 404, HTTP 401, or anything else)

{-# LANGUAGE DeriveDataTypeable, NoMonomorphismRestriction #-}

module Web.Twitter
  ( 
    -- * Statuses
    updateStatus,
    uploadImage,
    publicTimeline,
    homeTimeline,
    friendsTimeline,
    authUserTimeline,
    userTimeline,
    getStatus,
    authGetStatus,
    search,
    Status(..),

    -- * Favorites
    Favorite(..),
    getFavorites,
    unFavorite,

    -- * Totals
    AccountTotals(..),
    getTotals,

    -- * Misc
    Option(..),
    TwitterException(..),
    mentions

  ) where

import Data.Maybe (fromJust)
import Web.Twitter.OAuth
import Control.Monad
import Control.Applicative ((<$>))
import Control.Monad.Trans (liftIO, MonadIO)
import Network.OAuth.Consumer
import Network.OAuth.Http.Request
import Network.OAuth.Http.Response
import Network.OAuth.Http.CurlHttpClient
import Text.JSON
import Control.Exception
import Data.Typeable (Typeable)
import qualified Data.ByteString.Lazy.Char8 as L8

-- | A type representing a single status update, or 'tweet'.
data Status = Status {
    user   :: String, -- ^ The username of the poster of the status.
    text   :: String, -- ^ The content of the status update.
    id_str :: String  -- ^ The status id as a string.
    } deriving (Eq, Show)

(!) = flip valFromObj

instance JSON Status where
    readJSON (JSObject tweet) = 
        case timelineParse of
            Ok _ -> timelineParse
            _    -> searchParse
      where timelineParse = do
                userObject <- tweet ! "user"
                user'       <- userObject ! "screen_name"
                text'       <- tweet ! "text"
                id_str'     <- tweet ! "id_str"
                return Status {user = user', text = text', id_str = id_str'}
            searchParse = do
                user'    <- tweet ! "from_user"
                text'    <- tweet ! "text"
                id_str'  <- tweet ! "id_str"
                return Status {user = user', text = text', id_str = id_str'}

    showJSON = undefined

-- | A type representing a single favorited tweet
data Favorite = Favorite { fcreated_at :: String
                           -- THE MOST INSIPID THING: 
                           -- if i change this to id_str, this will not compile
                         , fid_str     :: String
                         } deriving (Eq, Show)

-- [{"id_str"="...",...},{...},...]
instance JSON Favorite where
   readJSON (JSObject fav) =
      do
         fcreated_at' <- fav ! "created_at"
         fid_str'     <- fav ! "id_str"
         return Favorite { fcreated_at = fcreated_at', fid_str = fid_str' }

   showJSON = undefined

-- | A type representing the returned account totals
data AccountTotals = AccountTotals { friends   :: Integer
                                   , updates   :: Integer
                                   , followers :: Integer
                                   , favorites :: Integer
                                   } deriving (Eq, Show)

-- { "friends":34534,"followers":430980,... }
instance JSON AccountTotals where
   showJSON = undefined
   readJSON (JSObject tots) =
      do
         friends'   <- tots ! "friends"
         followers' <- tots ! "followers"
         favorites' <- tots ! "favorites"
         updates'   <- tots ! "updates"
         return AccountTotals { friends   = friends'
                              , updates   = updates'
                              , followers = followers'
                              , favorites = favorites'
                              }


-- | A type representing an error that happened while doing something Twitter-related.
data TwitterException
     = NotFound        -- ^ The requested object was not found.
     | AccessForbidden -- ^ You do not have permission to access the requested entity.
     | OtherError      -- ^ Something else went wrong.
     deriving (Eq, Show, Typeable)
instance Exception TwitterException

type StatusID = String
data Option = SinceID StatusID |
              MaxID StatusID |
              Count Integer |
              Page Integer |
              IncludeRTs Bool |
              UserID String |
              ScreenName String |
              PerPage Integer |
              Raw String String
              deriving (Show)

toQuery :: [Option] -> [(String, String)]
toQuery = map toQuery' where
  toQuery' opt =
      case opt of
          SinceID id       -> ("since_id", id)
          MaxID id         -> ("max_id", id)
          Count count      -> ("count", show count)
          Page page        -> ("page", show page)
          IncludeRTs True  -> ("include_rts", "true")
          IncludeRTs False -> ("include_rts", "false")
          UserID id        -> ("user_id", id)
          ScreenName name  -> ("screen_name", name)
          PerPage perPage  -> ("per_page", show perPage)
          Raw opt val      -> (opt, val)

makeJSON :: (JSON a) => Response -> Result a
makeJSON = decode . L8.unpack . rspPayload

buildRequest ::  Method -> String -> [(String, String)] -> Request
buildRequest method part query =
    (fromJust . parseURL $ "https://api.twitter.com/1/" ++ part ++ ".json") { method = method, qString = fromList query}
   -- note the call to parseURL returns a Maybe Request (created using the ReqHttp constructor)

doRequest :: Method -> String -> [(String, String)] -> OAuthMonadT IO Response
doRequest meth part query = signRq2 HMACSHA1 Nothing (buildRequest meth part query) >>= serviceRequest CurlClient
   -- note the call to signRq2 signs a Request

-- like buildRequest, but including a payload for multipart/form-data
buildRequestMultipart :: Method -> String -> [(String, String)] -> [FormDataPart] -> Request
buildRequestMultipart method part query payload =
   (fromJust . parseURL $ url) {
      method     = method,
      qString    = fromList query,
      reqHeaders = fromList [ ("Expect", "") ],
      multipartPayload = payload
   }
   where
      url = "https://upload.twitter.com/1/" ++ part ++ ".json"

-- like doRequest, but including a payload for multipart/form-data
doRequestMultipart :: Method -> String -> [(String, String)] -> [FormDataPart] -> OAuthMonadT IO Response
doRequestMultipart meth part query payload =
   signRq2 HMACSHA1 Nothing req >>= serviceRequest CurlClient
   where
      req = buildRequestMultipart meth part query payload

withoutAuth :: (Monad m) => OAuthMonadT m a -> m a
withoutAuth = runOAuthM (fromApplication $ Application "" "" OOB)

-- Run the parser on the given response, but throw the appropriate
-- error given by the HTTP error code if parsing fails
handleErrors :: (Response -> Result a) -> Response -> a
handleErrors parser rsp = case parser rsp of
    Ok parsed -> parsed
    Error _   -> case status rsp of 
                   401 -> throw AccessForbidden
                   404 -> throw NotFound
                   x   -> error $ "about to throw OtherError: status is " ++ (shows x "")
                   --_   -> throw OtherError

-- Take a timeline response and turn it into a list of results
parseTimeline :: JSON a => Response -> [a]
parseTimeline = handleErrors $ makeJSON >=> readJSON

-- | Update the authenticating user's timeline with the given status
-- string. Returns IO () always, but doesn't do any exception
-- handling. Someday I'll fix that.
updateStatus :: Token -> String -> IO ()
updateStatus token status = runOAuthM token $ do
    _ <- doRequest POST "statuses/update"  [("status",status)]
    return ()

-- | Update the authenticating user's timeline with a status and an uploaded image
uploadImage :: Token -> String -> FilePath -> IO ()
uploadImage token status imageName = runOAuthM token $ do
   _ <- doRequestMultipart POST "statuses/update_with_media" [] payload
   return ()

   where
      payload :: [FormDataPart]
      payload =
         [ FormDataPart
            { postName = "status"
            , contentType = Just "form-data"
            , content = ContentString status
            , showName = Nothing
            , extraHeaders = []
            }
         , FormDataPart
            { postName = "media[]"
            , contentType = Just "Content"
            , content = ContentFile imageName
            , showName = Nothing
            , extraHeaders = []
            }
         ]

-- | Unfavorite a tweet
unFavorite :: String -> Token -> IO [Favorite]
unFavorite id_str token = fmap (parseTimeline) . runOAuthM token $ doRequest POST ("favorites/destroy/" ++ id_str) []

-- | Get favorites
getFavorites :: [Option] -> Token -> IO [Favorite]
getFavorites opts token = fmap (parseTimeline) . runOAuthM token $ doRequest GET "favorites" $ toQuery opts

-- | Get account totals
getTotals :: Token -> IO AccountTotals
getTotals token = fmap (handleErrors $ makeJSON >=> readJSON) . runOAuthM token $ doRequest GET "account/totals" []

-- | Get the public timeline as a list of statuses.
publicTimeline :: IO [Status]
publicTimeline  = fmap parseTimeline . withoutAuth $ doRequest GET "statuses/public_timeline" []

-- | Get the last 20 updates of the authenticating user's home
-- timeline, meaning all their statuses and those of their
-- friends. Will throw an @AccessForbidden@ if your token is invalid.
homeTimeline :: Token -> [Option] -> IO [Status]
homeTimeline token opts = fmap parseTimeline . runOAuthM token $ doRequest GET "statuses/home_timeline" (toQuery opts)

-- | Get the authenticating user's friends timeline. This is the same
-- as their home timeline, except it excludes RTs by default. Note
-- that if 5 of the last 20 tweets were RTs, this will only return 15
-- statuses.
friendsTimeline :: Token -> [Option] -> IO [Status]
friendsTimeline token opts = fmap parseTimeline . runOAuthM token $ do
    putToken token
    doRequest GET "statuses/friends_timeline" (toQuery opts)

-- | Get the last 20 tweets, without RTs, of the given username,
-- without authentication. If this throws an @AccessForbidden@ error,
-- the user's timeline is protected.
userTimeline :: String -> [Option] ->  IO [Status]
userTimeline name opts = fmap parseTimeline . withoutAuth $ doRequest GET "statuses/user_timeline" (("screen_name", name) : toQuery opts)

-- | Get the last 20 updates, without RTs, of the given username, with
-- authentication. If this throws an @AccessForbidden@ error, their
-- timeline is protected and you aren't allowed to see it.
authUserTimeline :: Token -> String -> [Option] -> IO [Status]
authUserTimeline token name opts = fmap parseTimeline . runOAuthM token $ doRequest GET "statuses/user_timeline" (("screen_name", name) : toQuery opts)

-- | Get the last 20 mentions of the authenticating user.
mentions :: Token -> [Option] -> IO [Status]
mentions token opts = fmap parseTimeline . runOAuthM token $ doRequest GET "statuses/mentions" (toQuery opts)

-- | Get a @Status@ corresponding to the given id, without authentication.
getStatus :: String -> IO Status
getStatus id_str = withoutAuth $ do
    rsp <- doRequest GET "statuses/show" [("id", id_str)]
    return . handleErrors (makeJSON >=> readJSON) $ rsp

-- | Get a @Status@ corresponding to the given id, with authentication.
authGetStatus :: Token -> String -> [Option] -> IO Status
authGetStatus token tweetId opts = runOAuthM token $ do
    rsp <- doRequest GET ("statuses/show/" ++ tweetId) (toQuery opts)
    return . handleErrors (makeJSON >=> readJSON) $ rsp

-- | Search for the given query.
search :: String -> [Option] -> IO [Status]
search query opts = withoutAuth $ do
    let req = (fromJust . parseURL $ "https://search.twitter.com/search.json") { method = GET, qString = fromList $ ("q", query) : toQuery opts }
    rsp <- signRq2 HMACSHA1 Nothing req >>= serviceRequest CurlClient
    return . handleErrors (makeJSON >=> parseSearch) $ rsp
    where parseSearch  = (mapM readJSON =<<) . (! "results") 


