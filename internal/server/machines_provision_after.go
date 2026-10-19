package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// opProvisionAfterCreate is the create chain's child that queues the provision orchestration once the machine is built and started.
const opProvisionAfterCreate = "machine_provision_after_create"

func (s *Server) registerProvisionExecutors() {
	s.tasks.Register(opProvisionAfterCreate, tasks.Executor{Run: s.provisionAfterCreateTask})
}

// provisionAfterCreateTask validates the stored document as POST /api/machines/{name}/provision does, resolves the transport and queues the provision orchestration with the boot skipped, the chain's start child having run.
func (s *Server) provisionAfterCreateTask(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, err := s.machines.Get(ctx, task.MachineName)
	if err != nil {
		return fmt.Errorf("machine %s: %w", task.MachineName, err)
	}
	validation, reason := s.validateProvisionRequest(ctx, machine)
	if reason != "" {
		return errors.New(reason)
	}
	if reason = resolveTransport(ctx, machine, validation); reason != "" {
		return errors.New(reason)
	}
	reason, needsConfirmation := s.hostHooksPreflight(ctx, machine, validation, false)
	if reason != "" {
		return errors.New(reason)
	}
	if needsConfirmation {
		return errors.New("the document carries host-target hooks that need the one-time confirmation: POST /api/machines/" +
			machine.Name + "/provision with confirm_host_hooks")
	}
	parentID, chain, _, err := s.startProvisionPipeline(ctx, machine, validation, true, task.CreatedBy)
	if err != nil {
		return err
	}
	out.Write("stdout", fmt.Sprintf("Provision orchestration %s queued with %d steps\n", parentID, len(chain)))
	return nil
}
