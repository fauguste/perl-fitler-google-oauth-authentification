perl-fitler-google-oauth-authentification
=========================================

This project is a perl filter for apache. It handles authentication for your web application using google oauth authentication.

![alt tag](https://raw.githubusercontent.com/fauguste/perl-fitler-google-oauth-authentification/master/schema%20mod%20perl%20google%20oauth.jpg)

This filter handles identification management for your web application. You can restrict application access for one email domain name.

This filter is simple to install and to use. It delegates authentication and identification to google.

With this filter, website authentication becomes easy. 

1) Subscribe to google api you have to register your web application at google apis console : 
 
https://code.google.com/apis/console/

2) Download The following perl libraries are needed :

```
apt-get install libjson-perl
apt-get install libcrypt-ssleay-perl
apt-get install libdigest-hmac-perl
apt-get install libapache2-mod-perl2
```

Download perl-filter-google-oauth-authentification and put it on your perl path.

3) Apache configuration

```
        <Location />
                PerlOptions +GlobalRequest
                PerlFixupHandler GoogleOauth::oauth
                # Call back (5), must be a child of the previous location.
                PerlSetVar OauthRedirectUri "http://oauth.exemple.com/oauth2callback"
                # Your project ClientId given by Google at https://code.google.com/apis/console/
                PerlSetVar OauthClientId "YOURVALUE.apps.googleusercontent.com"
                # Your project secret key given at https://code.google.com/apis/console/
                PerlSetVar OauthSecretKey "YOURVALUE"
                # Your cookie name
                PerlSetVar OauthCookieName "fred"
                # The cookie duration
                PerlSetVar OauthCookieDuration "3600"
                # The email domain name to grant access to your application (optional). Any google-authentified user if not present.
                PerlSetVar OauthDomainName "gmail.com"
        </Location>
```
