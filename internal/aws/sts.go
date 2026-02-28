package aws

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Credentials holds temporary AWS credentials from STS.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey  string
	SessionToken    string
	Expiration      time.Time
}

// stsResponse is the XML response from AssumeRoleWithWebIdentity.
type stsResponse struct {
	XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
	Result  stsResult `xml:"AssumeRoleWithWebIdentityResult"`
}

type stsResult struct {
	Credentials stsCredentials `xml:"Credentials"`
}

type stsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey  string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

// stsErrorResponse is the XML error response from STS.
type stsErrorResponse struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   stsError `xml:"Error"`
}

type stsError struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// AssumeRoleWithWebIdentity calls STS to assume an IAM role using a JWT.
func AssumeRoleWithWebIdentity(roleARN, sessionName, token, region string) (*Credentials, error) {
	endpoint := "https://sts.amazonaws.com"
	if region != "" {
		endpoint = fmt.Sprintf("https://sts.%s.amazonaws.com", region)
	}

	params := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {roleARN},
		"RoleSessionName":  {sessionName},
		"WebIdentityToken": {token},
	}

	resp, err := http.PostForm(endpoint, params)
	if err != nil {
		return nil, fmt.Errorf("STS request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read STS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp stsErrorResponse
		if xmlErr := xml.Unmarshal(body, &errResp); xmlErr == nil {
			return nil, fmt.Errorf("STS error (%s): %s", errResp.Error.Code, errResp.Error.Message)
		}
		return nil, fmt.Errorf("STS request failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var stsResp stsResponse
	if err := xml.Unmarshal(body, &stsResp); err != nil {
		return nil, fmt.Errorf("parse STS response: %w", err)
	}

	expiration, err := time.Parse(time.RFC3339, stsResp.Result.Credentials.Expiration)
	if err != nil {
		return nil, fmt.Errorf("parse expiration: %w", err)
	}

	return &Credentials{
		AccessKeyID:     stsResp.Result.Credentials.AccessKeyID,
		SecretAccessKey:  stsResp.Result.Credentials.SecretAccessKey,
		SessionToken:    stsResp.Result.Credentials.SessionToken,
		Expiration:      expiration,
	}, nil
}
