package redischaos

import (
	"context"
	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
	"github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/utils"
	"github.com/go-logr/logr"
)

type ObserveImpl struct {

	Log logr.Logger

	decoder *utils.ContainerRecordDecoder
}

func (o ObserveImpl) Watch(ctx context.Context, index int, records []*v1alpha1.Record, obj v1alpha1.InnerObject) (v1alpha1.Phase, error) {
	return "", nil
}

