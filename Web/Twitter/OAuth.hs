-- |
-- Module: Web.Twitter.OAuth
--
-- Maintainer: Kevin Cantu <me@kevincantu.org>
-- Stability: experimental
--
-- Wrappers using hoauth and libcurl for use with the Twitter API.

module Web.Twitter.OAuth
       ( getAuthenticateURL
       , makeToken
       , Consumer(..)
       , authenticate
       , singleAccessToken
       , writeToken
       , readToken
       ) where

import Data.Maybe (fromJust)
import Control.Applicative ((<$>))
import Control.Monad.Trans (MonadIO, liftIO)
import Network.OAuth.Consumer
import Network.OAuth.Http.Request
import Network.OAuth.Http.CurlHttpClient
import qualified Data.ByteString.Lazy as L
import Data.Binary as B

reqUrl :: Request
reqUrl = fromJust . parseURL $ "https://api.twitter.com/oauth/request_token"

accUrl :: Request
accUrl = fromJust . parseURL $ "https://api.twitter.com/oauth/access_token"

authUrl :: Token -> [Char]
authUrl = ("https://api.twitter.com/oauth/authorize?oauth_token=" ++)
            . findWithDefault ("oauth_token","") . oauthParams

request :: SigMethod -> Maybe Realm -> Request -> OAuthMonadT IO Token
request meth realm req = signRq2 meth realm req >>= oauthRequest CurlClient
-- note the call to signRq2 signs a Request

data Consumer = Consumer
    { key :: String
    , secret :: String }
    deriving (Show, Eq)

getAuthenticateURL :: Consumer -> OAuthMonadT IO String
getAuthenticateURL consumer = do
    ignite $ Application (key consumer) (secret consumer) OOB 
    _ <- request HMACSHA1 Nothing reqUrl
    authUrl <$> getToken

makeToken :: String -> OAuthMonadT IO Token
makeToken answer = do
    token <- getToken
    putToken $ injectOAuthVerifier answer token
    _ <- request HMACSHA1 Nothing accUrl
    getToken

authenticate :: Consumer -> IO Token
authenticate consumer = runOAuthM (fromApplication $ Application (key consumer) (secret consumer) OOB) $ do
    url <- getAuthenticateURL consumer
    liftIO . putStr $ "open " ++ url ++ "\nverifier: "
    makeToken =<< liftIO getLine

singleAccessToken :: Consumer -> String -> String -> IO Token
singleAccessToken consumer accToken accSecret = runOAuthM (fromApplication app) $ do
    let newToken = [("oauth_token", accToken)
                   ,("oauth_token_secret", accSecret)]
    ignite app
    token <- getToken
    return $ AccessToken app (fromList newToken `union` oauthParams token)
  where
    app = Application (key consumer) (secret consumer) OOB

writeToken :: Token -> FilePath -> IO ()
writeToken token path = L.writeFile path (encode token)

readToken :: FilePath -> IO Token
readToken path = fmap decode (L.readFile path)
