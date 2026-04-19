package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// IncidentLocker attempts a best-effort, cluster-wide dedup for an incident+phase
// using a coordination.k8s.io/v1 Lease. One replica's collection is enough per
// (node, phase, incident). A lease that outlives a crashed holder eventually
// expires, at which point a later webhook for the same incident can take over.
//
// Leases are NOT released on success: the TTL itself is the dedup window. The
// caller relies on incidents being uniquely keyed by startsAt, so a flapping
// node legitimately produces new (and newly-named) leases on each incident.
type IncidentLocker struct {
	client    kubernetes.Interface
	namespace string
	holder    string // pod name; whoever created the lease owns it
	ttl       time.Duration
	log       *slog.Logger
}

func newIncidentLocker(client kubernetes.Interface, namespace, holder string, ttl time.Duration, log *slog.Logger) *IncidentLocker {
	return &IncidentLocker{
		client:    client,
		namespace: namespace,
		holder:    holder,
		ttl:       ttl,
		log:       log,
	}
}

// leaseName returns a DNS-1123-safe name for the lease. Node labels from k8s
// are already conforming; the startsAt epoch is unique per incident.
func leaseName(node, phase string, startsAt time.Time) string {
	return fmt.Sprintf("ndbg-%s-%s-%d", node, phase, startsAt.Unix())
}

// Acquire returns true if this caller should proceed with collection. It first
// attempts to Create the Lease; on AlreadyExists it re-reads and steals if the
// existing record is past its TTL.
func (l *IncidentLocker) Acquire(ctx context.Context, name string) (bool, error) {
	now := metav1.NewMicroTime(time.Now())
	ttl := int32(l.ttl.Seconds())
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: l.namespace,
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       &l.holder,
			LeaseDurationSeconds: &ttl,
			AcquireTime:          &now,
			RenewTime:            &now,
		},
	}

	_, err := l.client.CoordinationV1().Leases(l.namespace).Create(ctx, lease, metav1.CreateOptions{})
	if err == nil {
		return true, nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return false, fmt.Errorf("create lease %s: %w", name, err)
	}

	existing, gerr := l.client.CoordinationV1().Leases(l.namespace).Get(ctx, name, metav1.GetOptions{})
	if gerr != nil {
		return false, fmt.Errorf("get existing lease %s: %w", name, gerr)
	}
	if !leaseExpired(existing) {
		holder := "?"
		if existing.Spec.HolderIdentity != nil {
			holder = *existing.Spec.HolderIdentity
		}
		l.log.Info("lease held by another replica, dropping", "lease", name, "holder", holder)
		return false, nil
	}

	existing.Spec.HolderIdentity = &l.holder
	existing.Spec.LeaseDurationSeconds = &ttl
	existing.Spec.AcquireTime = &now
	existing.Spec.RenewTime = &now
	if _, err := l.client.CoordinationV1().Leases(l.namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsConflict(err) {
			l.log.Info("lost race stealing expired lease", "lease", name)
			return false, nil
		}
		return false, fmt.Errorf("steal expired lease %s: %w", name, err)
	}
	l.log.Info("stole expired lease", "lease", name)
	return true, nil
}

func leaseExpired(l *coordinationv1.Lease) bool {
	if l.Spec.RenewTime == nil || l.Spec.LeaseDurationSeconds == nil {
		return true
	}
	return time.Since(l.Spec.RenewTime.Time) > time.Duration(*l.Spec.LeaseDurationSeconds)*time.Second
}
