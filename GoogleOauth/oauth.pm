#
# Copyright (c) 2012 frederic.auguste@gmail.com
#
package GoogleOauth::oauth;

use Apache2::Const -compile => qw(OK REDIRECT HTTP_GONE HTTP_INTERNAL_SERVER_ERROR HTTP_NON_AUTHORITATIVE);
use Apache2::ServerRec   ();
use Apache2::RequestRec  ();
use Apache2::RequestUtil ();
use Apache2::Response    ();
use Apache2::RequestIO();
use Apache2::URI ();
use URI::Escape;
use URI::URL;
use APR::Table;
use Apache2::Log;
use CGI qw(:standard);
use CGI::Cookie;
use LWP::UserAgent;
use HTML::Parse;
use HTTP::Request::Common;
use JSON;
use JSON::WebToken;
use MIME::Base64 qw(encode_base64);
use Digest::HMAC_SHA1;


sub handler {
  # Parameters
  my $r = shift;
  # Ending point of the google oauth api
  my $endPoint = "https://accounts.google.com/o/oauth2/auth";
  # search for profil and email information
  my $scope = uri_escape("openid email profile");
  my $verifyTokenUrl = "https://accounts.google.com/o/oauth2/token";
  # Url to redirect 
  my $state = $r->construct_url();
  # Url for create the cookie
  my $redirectURI = $r->dir_config("OauthRedirectUri");
  # Client Id generate by google
  my $clientId = uri_escape($r->dir_config("OauthClientId"));
  # Secret key generate by google
  my $secretKey = $r->dir_config("OauthSecretKey");
  # Cookie name
  my $cookieName = $r->dir_config("OauthCookieName");
  # Cookie duration in second
  my $cookieDuration = $r->dir_config("OauthCookieDuration");
  # HMAC digest
  my $hmac = Digest::HMAC_SHA1->new($secretKey);
  # Domain name autorized to acces
  my $domainName = $r->dir_config("OauthDomainName") || '';

  # 1. Already authentify ?
  %cookies = CGI::Cookie->fetch;
  if (exists $cookies{$cookieName}) {
    my $userCookie = $cookies{$cookieName};
    my %cookieValue = $userCookie->value();
    my $endTimeCookie = $cookieValue{'endTime'};
    # cookie not expried ?
    if($endTimeCookie gt time) {
      my $emailCookie = $cookieValue{'email'};
      my $keyCookie = $cookieValue{'key'};
      $hmac->reset();
      $hmac->add($endTimeCookie . $emailCookie);
      my $keyToVerify = encode_base64($hmac->digest);
      # Is a valid cookie ? 
      if($keyCookie eq $keyToVerify) {
         return Apache2::Const::OK;
      }
    }
  }

  $url1 = new URI::URL $r->construct_url();
  $url2 = new URI::URL $r->dir_config("OauthRedirectUri");
  # 2. Validation authentification
  if ($url1->path() eq $url2->path()) {
       my $redictInitialeUrl = param('state');
       my $code = param('code');
       $url3 = new URI::URL $redictInitialeUrl;
       # For never indefinilty loop
       if($url3->path() eq $url2->path()) {
          $r->log->error("Authentification loop");
          return Apache2::Const::HTTP_GONE;
       }
       my $ua = new LWP::UserAgent;
       $ua->timeout(5);
       # Verify token 
       my $req = POST $verifyTokenUrl, 
                      ['code' => $code, 
                       'client_id' => $clientId, 
                       'client_secret' => $secretKey, 
                       'redirect_uri' => $redirectURI, 
                       'grant_type' => 'authorization_code'];
       my $response = $ua->request($req);

       if($response->code eq '200') {
          # Get the user information 
          my $resToken = from_json($response->content());
          my $id_token = $resToken->{'id_token'};
          my $claims = JSON::WebToken->decode($id_token, '', 0);
          my $email = $claims->{'email'};

          my $endTime = time + $cookieDuration;
          my $email = $claims->{'email'};
          if($domainName ne '') { # Check domain 
            if($claims->{'hd'} ne $domainName) {
              $r->log->info("User $email try to access to $redictInitialeUrl");
              return Apache2::Const::HTTP_NON_AUTHORITATIVE;
            }
          }
          $hmac->reset();
          $hmac->add($endTime . $email);
          my $key = encode_base64($hmac->digest);
          $query = new CGI;
          $cookie = $query->cookie(-name=>$cookieName,
                         -value=>{'email'=>$email, 'endTime'=>$endTime, 'key'=>$key},
                         -expires=>"+365d",
                         -path=>'/');
          print $query->header(-cookie=>$cookie);
          $r->err_headers_out->add( 'Location' => $redictInitialeUrl);
          $r->log->info("User $email access to $redictInitialeUrl");
          return Apache2::Const::REDIRECT;
       }
       else {
         $r->log->error("Erreur while verifying token. Status : " . $response->code . " Response : " . $response->as_string);
         return Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
       }
       # Url de construction des données.
       return Apache2::Const::OK;
  }

  # No valide cookie : Redirect to authentification 
  $redirectURI = uri_escape($redirectURI);
  my $redirectTo = "$endPoint?scope=$scope&state=$state&redirect_uri=$redirectURI&response_type=code&client_id=$clientId&approval_prompt=auto";
  if($domainName ne '') {
    $redirectTo .= "&hd=$domainName";
  }
  $r->err_headers_out->add( 'Location' => $redirectTo);
  return Apache2::Const::REDIRECT;
}
1;
