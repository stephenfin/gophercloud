package common

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"math/rand"
	urllib "net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
)

// Type SignatureMethod is a OAuth1 SignatureMethod type.
type SignatureMethod string

const (
	// HMACSHA1 is a recommended OAuth1 signature method.
	HMACSHA1 SignatureMethod = "HMAC-SHA1"

	// PLAINTEXT signature method is not recommended to be used in
	// production environment.
	PLAINTEXT SignatureMethod = "PLAINTEXT"
)

type OAuth1SignatureOptions struct {
	// Callback is ...
	Callback string

	// Nonce is an OAuth1 request nonce. Nonce must be a random string,
	// uniquely generated for each request. Will be generated automatically
	// when it is not set.
	Nonce string

	// SignatureMethod is the OAuth1 signature method the Consumer used
	// to sign the request. Supported values are "HMAC-SHA1" or "PLAINTEXT".
	// "PLAINTEXT" is not recommended for production usage.
	SignatureMethod SignatureMethod

	// Timestamp is an OAuth1 request timestamp. If nil, current Unix
	// timestamp will be used.
	Timestamp *time.Time

	// OAuthToken is the OAuth1 Request Token.
	Token string

	// OAuthvTokenSecret is the OAuth1 Request Token Secret. Used to generate
	// an OAuth1 request signature.
	TokenSecret string

	// Verifier if the OAuth1 verification code.
	Verifier string
}

func BuildOAuth1AuthorizationHeader(consumerKey, consumerSecret, url, method string, options *OAuth1SignatureOptions) (string, error) {
	var callback string
	var nonce string
	var signatureMethod SignatureMethod
	var timestamp *time.Time
	var token string
	var tokenSecret string
	var verifier string

	if options != nil {
		callback = options.Callback
		nonce = options.Nonce
		signatureMethod = options.SignatureMethod
		timestamp = options.Timestamp
		token = options.Token
		tokenSecret = options.TokenSecret
		verifier = options.Verifier
	}

	if signatureMethod == "" {
		signatureMethod = HMACSHA1
	}

	opts := struct {
		// OAuthConsumerKey is the OAuth1 Consumer Key.
		OAuthConsumerKey string `q:"oauth_consumer_key" required:"true"`
		// OAuthToken is the OAuth1 Request Token.
		OAuthToken string `q:"oauth_token"`
		// OAuthSignatureMethod is the OAuth1 signature method the Consumer used
		// to sign the request. Supported values are "HMAC-SHA1" or "PLAINTEXT".
		// "PLAINTEXT" is not recommended for production usage.
		OAuthSignatureMethod SignatureMethod `q:"oauth_signature_method" required:"true"`
		// OAuthNonce is an OAuth1 request nonce. Nonce must be a random string,
		// uniquely generated for each request. Will be generated automatically
		// when it is not set.
		OAuthNonce string `q:"oauth_nonce"`
		// OAuthVerifier if the OAuth1 verification code.
		OAuthVerifier string `q:"oauth_verifier"`
	}{
		OAuthConsumerKey:     consumerKey,
		OAuthToken:           token,
		OAuthSignatureMethod: signatureMethod,
		OAuthNonce:           nonce,
		OAuthVerifier:        verifier,
	}

	q, err := buildOAuth1QueryString(opts, timestamp, callback)
	if err != nil {
		return "", err
	}

	signatureKeys := []string{consumerSecret}
	if tokenSecret != "" {
		signatureKeys = append(signatureKeys, tokenSecret)
	}

	stringToSign := buildStringToSign(method, url, q.Query())
	signature := urllib.QueryEscape(signString(opts.OAuthSignatureMethod, stringToSign, signatureKeys))

	authHeader := buildAuthHeader(q.Query(), signature)

	return authHeader, nil
}

// The following are small helper functions used to help build the signature.

// buildOAuth1QueryString builds a URLEncoded parameters string specific for
// OAuth1-based requests.
func buildOAuth1QueryString(opts any, timestamp *time.Time, callback string) (*urllib.URL, error) {
	q, err := gophercloud.BuildQueryString(opts)
	if err != nil {
		return nil, err
	}

	query := q.Query()

	if timestamp != nil {
		// use provided timestamp
		query.Set("oauth_timestamp", strconv.FormatInt(timestamp.Unix(), 10))
	} else {
		// use current timestamp
		query.Set("oauth_timestamp", strconv.FormatInt(time.Now().UTC().Unix(), 10))
	}

	if query.Get("oauth_nonce") == "" {
		// when nonce is not set, generate a random one
		query.Set("oauth_nonce", strconv.FormatInt(rand.Int63(), 10)+query.Get("oauth_timestamp"))
	}

	if callback != "" {
		query.Set("oauth_callback", callback)
	}
	query.Set("oauth_version", "1.0")

	return &urllib.URL{RawQuery: query.Encode()}, nil
}

// buildStringToSign builds a string to be signed.
func buildStringToSign(method string, u string, query urllib.Values) []byte {
	parsedURL, _ := urllib.Parse(u)
	p := parsedURL.Port()
	s := parsedURL.Scheme

	// Default scheme port must be stripped
	if s == "http" && p == "80" || s == "https" && p == "443" {
		parsedURL.Host = strings.TrimSuffix(parsedURL.Host, ":"+p)
	}

	// Ensure that URL doesn't contain queries
	parsedURL.RawQuery = ""

	v := strings.Join(
		[]string{method, urllib.QueryEscape(parsedURL.String()), urllib.QueryEscape(query.Encode())}, "&")

	return []byte(v)
}

// signString signs a string using an OAuth1 signature method.
func signString(signatureMethod SignatureMethod, strToSign []byte, signatureKeys []string) string {
	var key []byte
	for i, k := range signatureKeys {
		key = append(key, []byte(urllib.QueryEscape(k))...)
		if i == 0 {
			key = append(key, '&')
		}
	}

	var signedString string
	switch signatureMethod {
	case PLAINTEXT:
		signedString = string(key)
	default:
		h := hmac.New(sha1.New, key)
		h.Write(strToSign)
		signedString = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}

	return signedString
}

// buildAuthHeader generates an OAuth1 Authorization header with a signature
// calculated using an OAuth1 signature method.
func buildAuthHeader(query urllib.Values, signature string) string {
	var authHeader []string
	var keys []string
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		for _, v := range query[k] {
			authHeader = append(authHeader, fmt.Sprintf("%s=%q", k, urllib.QueryEscape(v)))
		}
	}

	authHeader = append(authHeader, fmt.Sprintf("oauth_signature=%q", signature))

	return "OAuth " + strings.Join(authHeader, ", ")
}
