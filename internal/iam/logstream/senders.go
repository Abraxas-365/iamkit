package logstream

import "context"

// Senders routes a batch to the Sender of its destination: the one
// dispatcher the service sends through.
type Senders map[string]Sender

var _ Sender = Senders(nil)

func (s Senders) Send(ctx context.Context, batch Outbound) Outcome {
	sender, ok := s[batch.Destination]
	if !ok {
		return OutcomeOf(0, "no sender for destination "+batch.Destination)
	}
	return sender.Send(ctx, batch)
}
