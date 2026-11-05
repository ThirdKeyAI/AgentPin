package wba

import (
	"fmt"

	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
)

func directoryMessage(authority string, headers []httpsig.Header) (httpsig.Message, error) {
	req, err := httpsig.NewRequest("GET", "https://"+authority+DirectoryPath)
	if err != nil {
		return httpsig.Message{}, err
	}
	return httpsig.ResponseMessage(&httpsig.Response{Status: 200, Headers: headers}, req), nil
}

var directoryComponents = []httpsig.Component{
	httpsig.OfRequest("@authority"),
	httpsig.NewComponent("content-digest"),
}

// SignDirectoryResponse returns the response fields for a signed key
// directory (Appendix B.1): Content-Digest plus one
// Signature-Input/Signature pair per key (labels binding0, binding1, ...),
// each covering "@authority";req and content-digest. authority is the host
// (and non-default port) the directory was requested on.
func SignDirectoryResponse(body []byte, authority string, keys []PrivateKey, created, validitySecs int64) ([]httpsig.Header, error) {
	if validitySecs < 1 || validitySecs > MaxValiditySecs {
		return nil, wbaErr("validity_secs must be between 1 and 86400")
	}
	digest := httpsig.ContentDigest(body)
	msg, err := directoryMessage(authority, []httpsig.Header{{Name: "Content-Digest", Value: digest}})
	if err != nil {
		return nil, err
	}
	out := []httpsig.Header{{Name: "Content-Digest", Value: digest}}
	for i, k := range keys {
		params := []httpsig.Param{
			httpsig.Created(created),
			httpsig.Expires(created + validitySecs),
			httpsig.KeyID(Thumbprint(k.PublicKey())),
			httpsig.Tag(DirectoryTag),
		}
		f, err := httpsig.Sign(msg, fmt.Sprintf("binding%d", i), directoryComponents, params, k)
		if err != nil {
			return nil, err
		}
		out = append(out,
			httpsig.Header{Name: "Signature-Input", Value: f.SignatureInput},
			httpsig.Header{Name: "Signature", Value: f.Signature})
	}
	return out, nil
}

// VerifyDirectoryResponse checks a directory response's possession proofs
// (Appendix B.1) and returns only the keys that carry a valid one. The
// Content-Digest must match body; a proof must use the key it names, cover
// "@authority";req and content-digest, and be neither future-dated nor
// expired.
func VerifyDirectoryResponse(body []byte, headers []httpsig.Header, authority string, now, clockSkewSecs int64) (*Directory, error) {
	dir, err := ParseDirectory(body)
	if err != nil {
		return nil, err
	}
	if !httpsig.ContentDigestMatches(headers, body) {
		return nil, wbaErr("directory Content-Digest does not match the body")
	}
	msg, err := directoryMessage(authority, headers)
	if err != nil {
		return nil, err
	}
	sigs, err := httpsig.ParseSignatures(headers)
	if err != nil {
		return nil, err
	}
	proven := &Directory{Keys: []JWK{}}
	for _, j := range dir.Keys {
		pk, err := j.PublicKey()
		if err != nil {
			continue
		}
		tp := Thumbprint(pk)
		for _, s := range sigs {
			p := s.Params
			if p.Tag != nil && *p.Tag == DirectoryTag &&
				p.KeyID != nil && *p.KeyID == tp &&
				p.Created != nil && *p.Created <= now+clockSkewSecs &&
				p.Expires != nil && now-clockSkewSecs <= *p.Expires &&
				s.Covers(directoryComponents[0]) && s.Covers(directoryComponents[1]) &&
				httpsig.Verify(msg, s, pk) == nil {
				proven.Keys = append(proven.Keys, j)
				break
			}
		}
	}
	return proven, nil
}
