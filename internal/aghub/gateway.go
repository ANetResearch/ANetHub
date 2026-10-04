package aghub

import (
	"net/http"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// The x402 resource gateway is removed, and its path is a tombstone.
//
// The gateway sold access to an agent's work over plain HTTP: it quoted a
// price read from the agent's public card, settled the payment on this
// hub's ledger and handed back a hub-signed voucher the buyer spent at the
// agent. Each half of that is gone in 0.3.0. Prices are no longer public:
// they travel only in the extended card the provider signs and sends end
// to end, so a hub has no price to quote and should not hold one. And a
// voucher is a bearer object this hub issued for work it never sees, which
// is a payment path beside the one task payments now take (the a2a-x402
// payment-required quote inside the sealed task, settled here).
//
// A plain HTTP x402 client is not left without a way in: it installs anet
// and calls through anet's local A2A interface, where anet signs the
// payment for it. The path answers 410 gateway_removed, whose sentence says
// exactly that, rather than 404: a client that learned this URL from an
// older document is told the gateway was taken away on purpose and where
// to go, instead of being left to wonder whether it mistyped.

// gatewayPath is the removed gateway's path, /x402/resource/{aid}/{capability};
// the tombstone covers every path below it.
const gatewayPath = "/x402/resource/"

// hGatewayRemoved answers every GET below gatewayPath with 410
// gateway_removed. It reads nothing of the request: no agent is looked up
// and a PAYMENT-SIGNATURE header is not decoded, so no payment sent to the
// old URL can move credit.
func hGatewayRemoved(w http.ResponseWriter, _ *http.Request) {
	wire3.Refuse(w, wire3.ReasonGatewayRemoved)
}
