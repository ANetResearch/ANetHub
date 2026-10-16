package federation

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
)

// POST /fed/v3/directory:bucket (sealed-sender §2.8, §2.9).
//
// A peer hub asks for one bucket of this hub's directory: the request and
// the answer are those of /directory:bucket, without partial, because the
// answer holds this hub's own entries only (SSR-W20). A hub asks its peers
// for the bucket a daemon asked it for, to merge the answers (SSR-W19), and
// for the bucket of a recipient whose home it resolves (SSR-H12 step 4). The
// entries are sealed under their AIDs: a peer learns which bucket was asked
// for, and opens only the entries of the AIDs it already knows.
//
// The bucket federation follows the delivery switch, not the discovery
// one: a hub that carries a peer's mail needs to find the home of its
// recipients and their keys, whatever it publishes of its own directory.

// bucketTimeout bounds one bucket request at the asking hub (SSR-W21): a
// peer that has not answered by then is missing from the merged answer.
const bucketTimeout = 5 * time.Second

// bucketBodyLimit bounds a /fed/v3/directory:bucket body, as
// /directory:bucket bounds its own: a prefix and a cursor in JSON.
const bucketBodyLimit = 4 << 10

// hBucket serves POST /fed/v3/directory:bucket.
func (s *Service) hBucket(w http.ResponseWriter, r *http.Request) {
	if _, body, ok := s.authPeer(w, r, relayauth.ActionFedBucket, s.Enabled(), bucketBodyLimit, nil); ok {
		s.kernel.ServeBucket(w, body)
	}
}

// Bucket asks the peer hub peerAID for one bucket with POST
// /fed/v3/directory:bucket, body being the JSON request of
// /directory:bucket, signed for fed_bucket. The response is the caller's to
// read and close. No answer within bucketTimeout is an error.
func (s *Service) Bucket(ctx context.Context, peerAID string, body []byte) (*http.Response, error) {
	p := s.deliveryPeer(peerAID)
	if p == nil {
		return nil, errNotADeliveryPeer(peerAID)
	}
	ctx, cancel := context.WithTimeout(ctx, bucketTimeout)
	resp, err := s.signer.Do(ctx, p.AID, relayauth.ActionFedBucket, Request{Method: http.MethodPost,
		URL: strings.TrimSuffix(p.Endpoint, "/") + "/fed/v3/directory:bucket", ContentType: "application/json", Body: body})
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = cancelOnClose{resp.Body, cancel}
	return resp, nil
}
