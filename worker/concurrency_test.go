package worker

import (
	"testing"
	"time"

	"cscan/scheduler"

	"github.com/stretchr/testify/assert"
)

func newTestWorker(concurrency int) *Worker {
	return &Worker{
		config:            WorkerConfig{Name: "test-worker", Concurrency: concurrency},
		logger:            NewWorkerLoggerLocal("test-worker"),
		resourceManager:   NewResourceManager(concurrency),
		adaptiveScheduler: NewAdaptiveScheduler(DefaultAdaptiveSchedulerConfig(concurrency)),
		taskChan:          make(chan *scheduler.TaskInfo, concurrency),
		stopChan:          make(chan struct{}),
		executorCount:     concurrency,
	}
}

func TestApplyConcurrencyIncreaseSyncsAllComponents(t *testing.T) {
	w := newTestWorker(5)

	w.applyConcurrency(20)

	assert.Equal(t, 20, w.config.Concurrency)
	assert.Equal(t, 20, w.adaptiveScheduler.GetCurrentConcurrency())
	assert.Equal(t, 20, w.resourceManager.GetResourceStatus().MaxConcurrency)
	// isRunning=false 时不补启协程
	assert.Equal(t, 5, w.executorCount)
}

func TestApplyConcurrencyDecrease(t *testing.T) {
	w := newTestWorker(10)

	w.applyConcurrency(2)

	assert.Equal(t, 2, w.config.Concurrency)
	assert.Equal(t, 2, w.adaptiveScheduler.GetCurrentConcurrency())
	assert.Equal(t, 2, w.resourceManager.GetResourceStatus().MaxConcurrency)
	// 协程数不缩减，由限流门自然收敛
	assert.Equal(t, 10, w.executorCount)
}

func TestApplyConcurrencyRejectsInvalidValues(t *testing.T) {
	w := newTestWorker(5)

	w.applyConcurrency(0)
	assert.Equal(t, 5, w.config.Concurrency)

	w.applyConcurrency(-3)
	assert.Equal(t, 5, w.config.Concurrency)
}

func TestApplyConcurrencyNoopWhenUnchanged(t *testing.T) {
	w := newTestWorker(5)

	w.applyConcurrency(5)

	assert.Equal(t, 5, w.config.Concurrency)
	assert.Equal(t, 5, w.executorCount)
}

func TestApplyConcurrencySpawnsExecutorsWhenRunning(t *testing.T) {
	w := newTestWorker(3)
	w.isRunning = true

	w.applyConcurrency(8)

	assert.Equal(t, 8, w.config.Concurrency)
	assert.Equal(t, 8, w.executorCount)

	// 关闭 stopChan 应让补启的协程全部退出
	close(w.stopChan)
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("spawned executors did not exit after stopChan closed")
	}
}

func TestAdaptiveSchedulerSetMaxConcurrencyRaisesCurrent(t *testing.T) {
	s := NewAdaptiveScheduler(DefaultAdaptiveSchedulerConfig(5))

	s.SetMaxConcurrency(20)
	assert.Equal(t, 20, s.GetCurrentConcurrency())

	s.SetMaxConcurrency(3)
	assert.Equal(t, 3, s.GetCurrentConcurrency())

	// 非法值不生效
	s.SetMaxConcurrency(0)
	assert.Equal(t, 3, s.GetCurrentConcurrency())
}
