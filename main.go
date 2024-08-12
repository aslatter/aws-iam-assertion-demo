package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func main() {
	err := mainErr()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: ", err)
		os.Exit(1)
	}
}

func mainErr() error {
	ctx := context.TODO()

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading aws configs: %s", err)
	}
	stsclient := sts.NewFromConfig(awsCfg)

	opts := stsclient.Options()
	endpoint, err := opts.EndpointResolverV2.ResolveEndpoint(ctx, sts.EndpointParameters{
		Region: &opts.Region,
	})
	if err != nil {
		return fmt.Errorf("resolving sts endpoint: %s", err)
	}

	// request to sign
	req, err := http.NewRequest("POST", endpoint.URI.String(), nil)
	if err != nil {
		return fmt.Errorf("creating request to sign: %s", err)
	}
	// we include the content-type in the signature to prevent mis-interpretation
	// of the signed payload-bytes
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("x-custom-audience", "foo/bar") // this could be the issuer url, for example
	// we can add any other custom headers to sign

	formBytes := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	payloadHash := sha256.Sum256(formBytes)
	hex.EncodeToString(payloadHash[:])

	c, err := awsCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("retrieving aws credentials: %s", err)
	}

	err = opts.HTTPSignerV4.SignHTTP(ctx, c, req, hex.EncodeToString(payloadHash[:]), "sts", opts.Region, time.Now())
	if err != nil {
		return fmt.Errorf("pre-signing sts request: %s", err)
	}

	// the client would then communicate:
	// - sts region
	// - request-signing date
	// - authorization
	// - x-amz-security-token (if present)

	type sig struct {
		StsRegion        string
		SigningDate      string
		Authorization    string
		AmzSecurityToken string
	}
	clientSig := sig{
		StsRegion:        opts.Region,
		SigningDate:      req.Header.Get("x-amz-date"),
		Authorization:    req.Header.Get("authorization"),
		AmzSecurityToken: req.Header.Get("x-amz-security-token"),
	}

	// the singed-uri and signed-headers would then be communicated to some issuer-service
	// for use as an assertion which can be used to prove AWS IAM identity. From this point
	// on the code in this function is operating as the persona of the issuer.

	// use the signed-uri to call the API
	// this is the part the remote-issuer would perform.
	// the remote issuer would also validate:
	// - URI host
	// - anything else in the payload

	// TODO - have an allow-list of region-ids or regex or something
	//        (the endpoint resolver doesn't appear to prevent url-injection via the region-name)
	stsEndpoint, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, sts.EndpointParameters{
		Region: &clientSig.StsRegion,
	})
	if err != nil {
		return fmt.Errorf("discovering sts endpoint for region %q: %s", clientSig.StsRegion, err)
	}

	// in reality the issuer would re-create the payload bytes (not re-use them from the client!).
	stsReq, err := http.NewRequestWithContext(ctx, "POST", stsEndpoint.URI.String(), bytes.NewReader(formBytes))
	if err != nil {
		return fmt.Errorf("creating sts request: %s", err)
	}

	// TODO - add headers from endpoint-resolver?

	stsReq.Header.Add("x-custom-audience", "foo/bar")
	stsReq.Header.Add("accept-encoding", "identity")
	stsReq.Header.Add("content-type", "application/x-www-form-urlencoded")
	// add details from client-request
	stsReq.Header.Add("x-amz-date", clientSig.SigningDate)
	stsReq.Header.Add("authorization", clientSig.Authorization)
	if clientSig.AmzSecurityToken != "" {
		stsReq.Header.Add("x-amz-security-token", clientSig.AmzSecurityToken)
	}

	resp, err := http.DefaultClient.Do(stsReq)
	if err != nil {
		return fmt.Errorf("calling sts: %s", err)
	}
	defer resp.Body.Close()

	fmt.Println("response status: ", resp.Status)

	// while we're here, show off what decoding the response would look
	// like.

	// at this point the issuer would validate that the discovered
	// IAM identity is allowed to do whatever it is the client is doing.
	// It may make sense to validate the action with additional custom
	// headers in the signature.

	type getCallerIdentityResponse struct {
		XMLName                 xml.Name `xml:"GetCallerIdentityResponse" json:"-"`
		GetCallerIdentityResult struct {
			Arn     string
			UserId  string
			Account string
		}
	}
	var identResponse getCallerIdentityResponse
	dec := xml.NewDecoder(resp.Body)
	err = dec.Decode(&identResponse)
	if err != nil {
		return fmt.Errorf("decoding xml response: %s", err)
	}

	dump(identResponse.GetCallerIdentityResult)

	return nil
}

func dump(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
