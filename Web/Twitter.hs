----------------------------------------------------
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
-----------------------------------------------------

{-# LANGUAGE DeriveDataTypeable, NoMonomorphismRestriction #-}

module Web.Twitter
       ( updateStatus,
         publicTimeline,
         homeTimeline,
         friendsTimeline,
         authUserTimeline,
         userTimeline,
         mentions,
         getStatus,
         authGetStatus,
         Status(..),
         TwitterException(..)
       ) where

import Data.Maybe (fromJust)
import Web.Twitter.OAuth
import Control.Monad
import Control.Applicative ((<$>))
import Control.Monad.Trans (liftIO, MonadIO)
import Network.OAuth.Consumer
import Network.OAuth.Http.Request
import Network.OAuth.Http.Response
import Network.OAuth.Http.HttpClient
import Text.JSON
import Control.Exception
import Data.Typeable (Typeable)
import qualified Data.ByteString.Lazy.Char8 as L8

-- | A type representing a single status update, or 'tweet'.
data Status = Status {
    user :: String, -- ^ The username of the poster of the status.
    text :: String  -- ^ The content of the status update.
    } deriving (Eq, Show)

-- | A type representing an error that happened while doing something Twitter-related.
data TwitterException
     = NotFound        -- ^ The requested object was not found.
     | AccessForbidden -- ^ You do not have permission to access the requested entity.
     | OtherError      -- ^ Something else went wrong.
     deriving (Eq, Show, Typeable)
instance Exception TwitterException

-- Turn a JSON object corresponding to a status into a Status object, but
-- error out if parsing fails.
makeStatus :: JSObject JSValue -> Result Status
makeStatus tweet = do
    userObject <- valFromObj "user" tweet
    user <- valFromObj "screen_name" userObject
    text <- valFromObj "text" tweet
    return Status {user = user, text = text}


makeJSON :: (JSON a) => Response -> Result a
makeJSON = decode . L8.unpack . rspPayload

buildRequest ::  Method -> String -> [(String, String)] -> Request
buildRequest method part query =
    (fromJust . parseURL $ "http://api.twitter.com/1/" ++ part ++ ".json") { method = method, qString = fromList query}

doRequest :: (MonadIO m, HttpClient m) => Method -> String -> [(String, String)] -> OAuthMonad m Response
doRequest meth part query = serviceRequest HMACSHA1 Nothing $ buildRequest meth part query

-- Run the parser on the given response, but throw the appropriate
-- error given by the HTTP error code if parsing fails
handleErrors :: (Response -> Result a) -> Response -> a
handleErrors parser rsp = case parser rsp of
    Ok parsed -> parsed
    Error _ -> case status rsp of 
        401 -> throw AccessForbidden
        404 -> throw NotFound
        _   -> throw OtherError

-- Take a timeline response and turn it into a list of Statuses.
parseTimeline :: Response -> [Status]
parseTimeline = handleErrors $ \rsp -> do 
    json <- makeJSON rsp
    tweets <- readJSONs json >>= mapM readJSON
    mapM makeStatus tweets

-- | Update the authenticating user's timeline with the given status
-- string. Returns IO () always, but doesn't do any exception
-- handling. Someday I'll fix that.
updateStatus :: Token -> String -> IO ()
updateStatus token status = unwrap $ do
    putToken token
    doRequest POST "statuses/update"  [("status", status)]
    return ()

-- | Get the public timeline as a list of statuses.
publicTimeline :: IO [Status]
publicTimeline  = fmap parseTimeline . unwrap $ doRequest GET "statuses/public_timeline" []

-- | Get the last 20 updates of the authenticating user's home
-- timeline, meaning all their statuses and those of their
-- friends. Will throw an @AccessForbidden@ if your token is invalid.
homeTimeline :: Token -> IO [Status]
homeTimeline token = fmap parseTimeline . unwrap $ do
    putToken token
    doRequest GET "statuses/home_timeline" []

-- | Get the authenticating user's friends timeline. This is the same
-- as their home timeline, except it excludes RTs by default. Note
-- that if 5 of the last 20 tweets were RTs, this will only return 15
-- statuses.
friendsTimeline :: Token -> IO [Status]
friendsTimeline token = fmap parseTimeline . unwrap $ do
    putToken token
    doRequest GET "statuses/friends_timeline" []

-- | Get the last 20 tweets, without RTs, of the given username,
-- without authentication. If this throws an @AccessForbidden@ error,
-- the user's timeline is protected.
userTimeline :: String -> IO [Status]
userTimeline name = fmap parseTimeline . unwrap $
    doRequest GET "statuses/user_timeline" [("screen_name", name)]

-- | Get the last 20 updates, without RTs, of the given username, with
-- authentication. If this throws an @AccessForbidden@ error, their
-- timeline is protected and you aren't allowed to see it.
authUserTimeline :: Token -> String -> IO [Status]
authUserTimeline token name = fmap parseTimeline . unwrap $ do
    putToken token
    doRequest GET "statuses/user_timeline" [("screen_name", name)]

-- | Get the last 20 mentions of the authenticating user.
mentions :: Token -> IO [Status]
mentions token = fmap parseTimeline . unwrap $ do
    putToken token
    doRequest GET "statuses/mentions" []

-- | Get a @Status@ corresponding to the given id, without authentication.
getStatus :: String -> IO Status
getStatus tweetId = unwrap $ do
    rsp <- doRequest GET ("statuses/show/" ++ tweetId) []
    return . handleErrors (makeJSON >=> makeStatus) $ rsp

-- | Get a @Status@ corresponding to the given id, with authentication
authGetStatus :: Token -> String -> IO Status
authGetStatus token tweetId = unwrap $ do
    putToken token
    rsp <- doRequest GET ("statuses/show/" ++ tweetId) []
    return . handleErrors (makeJSON >=> makeStatus) $ rsp