// Copyright 2021 Chaos Mesh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package experiment

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	chaosdaemonclient "github.com/chaos-mesh/chaos-mesh/pkg/chaosdaemon/client"
	"github.com/chaos-mesh/chaos-mesh/pkg/chaosdaemon/pb"
	grpcUtils "github.com/chaos-mesh/chaos-mesh/pkg/grpc"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
	"github.com/chaos-mesh/chaos-mesh/controllers/common/finalizers"
	"github.com/chaos-mesh/chaos-mesh/pkg/clientpool"
	config "github.com/chaos-mesh/chaos-mesh/pkg/config/dashboard"
	u "github.com/chaos-mesh/chaos-mesh/pkg/dashboard/apiserver/utils"
	"github.com/chaos-mesh/chaos-mesh/pkg/dashboard/core"
	"github.com/chaos-mesh/chaos-mesh/pkg/status"

	cconf "github.com/chaos-mesh/chaos-mesh/controllers/config"
)

var log = u.Log.WithName("experiments")

// Service defines a handler service for experiments.
type Service struct {
	archive core.ExperimentStore
	event   core.EventStore
	config  *config.ChaosDashboardConfig
	scheme  *runtime.Scheme
}

func NewService(
	archive core.ExperimentStore,
	event core.EventStore,
	config *config.ChaosDashboardConfig,
	scheme *runtime.Scheme,
) *Service {
	return &Service{
		archive: archive,
		event:   event,
		config:  config,
		scheme:  scheme,
	}
}

// Register experiments RouterGroup.
func Register(r *gin.RouterGroup, s *Service) {
	endpoint := r.Group("/experiments")

	endpoint.GET("", s.list)
	endpoint.POST("", s.create)
	endpoint.GET("/:uid", s.get)
	endpoint.DELETE("/:uid", s.delete)
	endpoint.GET("/:uid/observe", s.observe)
	endpoint.GET("/:uid/log", s.log)
	endpoint.DELETE("", s.batchDelete)
	endpoint.PUT("/pause/:uid", s.pause)
	endpoint.PUT("/start/:uid", s.start)
	endpoint.GET("/state", s.state)
	endpoint.POST("/upload", s.upload)
}

// Experiment defines the information of an experiment.
type Experiment struct {
	core.ObjectBase
	Status        status.ChaosStatus `json:"status"`
	FailedMessage string             `json:"failed_message,omitempty"`
}

// Detail adds KubeObjectDesc on Experiment.
type Detail struct {
	Experiment
	KubeObject core.KubeObjectDesc `json:"kube_object"`
}

// @Summary List chaos experiments.
// @Description Get chaos experiments from k8s clusters in real time.
// @Tags experiments
// @Produce json
// @Param namespace query string false "filter exps by namespace"
// @Param name query string false "filter exps by name"
// @Param kind query string false "filter exps by kind" Enums(PodChaos, NetworkChaos, IOChaos, StressChaos, KernelChaos, TimeChaos, DNSChaos, AWSChaos, GCPChaos, JVMChaos, HTTPChaos)
// @Param status query string false "filter exps by status" Enums(Injecting, Running, Finished, Paused)
// @Success 200 {array} Experiment
// @Failure 400 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments [get]
func (s *Service) list(c *gin.Context) {
	kubeCli, err := clientpool.ExtractTokenAndGetClient(c.Request.Header)
	if err != nil {
		u.SetAPIError(c, u.ErrBadRequest.WrapWithNoMessage(err))

		return
	}

	ns, name, kind := c.Query("namespace"), c.Query("name"), c.Query("kind")

	if ns == "" && !s.config.ClusterScoped && s.config.TargetNamespace != "" {
		ns = s.config.TargetNamespace

		log.V(1).Info("Replace query namespace with", ns)
	}

	exps := make([]*Experiment, 0)
	for k, chaosKind := range v1alpha1.AllKinds() {
		if kind != "" && k != kind {
			continue
		}

		list := chaosKind.SpawnList()
		if err := kubeCli.List(context.Background(), list, &client.ListOptions{Namespace: ns}); err != nil {
			u.SetAPImachineryError(c, err)

			return
		}

		for _, item := range list.GetItems() {
			chaosName := item.GetName()

			if name != "" && chaosName != name {
				continue
			}

			exps = append(exps, &Experiment{
				ObjectBase: core.ObjectBase{
					Namespace: item.GetNamespace(),
					Name:      chaosName,
					Kind:      item.GetObjectKind().GroupVersionKind().Kind,
					UID:       string(item.GetUID()),
					Created:   item.GetCreationTimestamp().Format(time.RFC3339),
				},
				Status: status.GetChaosStatus(item.(v1alpha1.InnerObject)),
			})
		}
	}

	sort.Slice(exps, func(i, j int) bool {
		return exps[i].Created > exps[j].Created
	})

	c.JSON(http.StatusOK, exps)
}

// @Summary Create a new chaos experiment.
// @Description Pass a JSON object to create a new chaos experiment. The schema for JSON is the same as the YAML schema for the Kubernetes object.
// @Tags experiments
// @Accept json
// @Produce json
// @Param chaos body map[string]interface{} true "the chaos definition"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments [post]
func (s *Service) create(c *gin.Context) {
	kubeCli, err := clientpool.ExtractTokenAndGetClient(c.Request.Header)
	if err != nil {
		u.SetAPIError(c, u.ErrBadRequest.WrapWithNoMessage(err))

		return
	}

	var exp map[string]interface{}
	if err = u.ShouldBindBodyWithJSON(c, &exp); err != nil {
		return
	}
	kind := exp["kind"].(string)

	if chaosKind, ok := v1alpha1.AllKinds()[kind]; ok {
		chaos := chaosKind.SpawnObject()
		reflect.ValueOf(chaos).Elem().FieldByName("ObjectMeta").Set(reflect.ValueOf(metav1.ObjectMeta{}))

		if err = u.ShouldBindBodyWithJSON(c, chaos); err != nil {
			return
		}

		if err = kubeCli.Create(context.Background(), chaos); err != nil {
			u.SetAPImachineryError(c, err)

			return
		}
	} else {
		u.SetAPIError(c, u.ErrBadRequest.New("Kind "+kind+" is not supported"))

		return
	}

	c.JSON(http.StatusOK, exp)
}

// @Summary Get a chaos experiment.
// @Description Get the chaos experiment's detail by uid.
// @Tags experiments
// @Produce json
// @Param uid path string true "the experiment uid"
// @Success 200 {object} Detail
// @Failure 400 {object} utils.APIError
// @Failure 404 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments/{uid} [get]
func (s *Service) get(c *gin.Context) {
	var (
		exp       *core.Experiment
		expDetail *Detail
	)

	kubeCli, err := clientpool.ExtractTokenAndGetClient(c.Request.Header)
	if err != nil {
		u.SetAPIError(c, u.ErrBadRequest.WrapWithNoMessage(err))

		return
	}

	uid := c.Param("uid")
	if exp, err = s.archive.FindByUID(context.Background(), uid); err != nil {
		if gorm.IsRecordNotFoundError(err) {
			u.SetAPIError(c, u.ErrNotFound.New("Experiment "+uid+" not found"))
		} else {
			u.SetAPIError(c, u.ErrInternalServer.WrapWithNoMessage(err))
		}

		return
	}

	ns, name, kind := exp.Namespace, exp.Name, exp.Kind

	if chaosKind, ok := v1alpha1.AllKinds()[kind]; ok {
		expDetail = s.findChaosInCluster(c, kubeCli, types.NamespacedName{Namespace: ns, Name: name}, chaosKind.SpawnObject())

		if expDetail == nil {
			return
		}
	} else {
		u.SetAPIError(c, u.ErrBadRequest.New("Kind "+kind+" is not supported"))

		return
	}

	c.JSON(http.StatusOK, expDetail)
}

func (s *Service) findChaosInCluster(c *gin.Context, kubeCli client.Client, namespacedName types.NamespacedName, chaos client.Object) *Detail {
	if err := kubeCli.Get(context.Background(), namespacedName, chaos); err != nil {
		u.SetAPImachineryError(c, err)

		return nil
	}

	gvk, err := apiutil.GVKForObject(chaos, s.scheme)
	if err != nil {
		u.SetAPImachineryError(c, err)

		return nil
	}

	kind := gvk.Kind

	return &Detail{
		Experiment: Experiment{
			ObjectBase: core.ObjectBase{
				Namespace: reflect.ValueOf(chaos).MethodByName("GetNamespace").Call(nil)[0].String(),
				Name:      reflect.ValueOf(chaos).MethodByName("GetName").Call(nil)[0].String(),
				Kind:      kind,
				UID:       reflect.ValueOf(chaos).MethodByName("GetUID").Call(nil)[0].String(),
				Created:   reflect.ValueOf(chaos).MethodByName("GetCreationTimestamp").Call(nil)[0].Interface().(metav1.Time).Format(time.RFC3339),
			},
			Status: status.GetChaosStatus(chaos.(v1alpha1.InnerObject)),
		},
		KubeObject: core.KubeObjectDesc{
			TypeMeta: metav1.TypeMeta{
				APIVersion: gvk.GroupVersion().String(),
				Kind:       kind,
			},
			Meta: core.KubeObjectMeta{
				Namespace:   reflect.ValueOf(chaos).Elem().FieldByName("Namespace").String(),
				Name:        reflect.ValueOf(chaos).Elem().FieldByName("Name").String(),
				Labels:      reflect.ValueOf(chaos).Elem().FieldByName("Labels").Interface().(map[string]string),
				Annotations: reflect.ValueOf(chaos).Elem().FieldByName("Annotations").Interface().(map[string]string),
			},
			Spec: reflect.ValueOf(chaos).Elem().FieldByName("Spec").Interface(),
		},
	}
}

// @Summary Delete a chaos experiment.
// @Description Delete the chaos experiment by uid.
// @Tags experiments
// @Produce json
// @Param uid path string true "the experiment uid"
// @Param force query string false "force" Enums(true, false)
// @Success 200 {object} utils.Response
// @Failure 400 {object} utils.APIError
// @Failure 404 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments/{uid} [delete]
func (s *Service) delete(c *gin.Context) {
	var (
		exp *core.Experiment
	)

	kubeCli, err := clientpool.ExtractTokenAndGetClient(c.Request.Header)
	if err != nil {
		u.SetAPIError(c, u.ErrBadRequest.WrapWithNoMessage(err))

		return
	}

	uid := c.Param("uid")
	if exp, err = s.archive.FindByUID(context.Background(), uid); err != nil {
		if gorm.IsRecordNotFoundError(err) {
			u.SetAPIError(c, u.ErrNotFound.New("Experiment "+uid+" not found"))
		} else {
			u.SetAPIError(c, u.ErrInternalServer.WrapWithNoMessage(err))
		}

		return
	}

	ns, name, kind, force := exp.Namespace, exp.Name, exp.Kind, c.DefaultQuery("force", "false")
	if ok := checkAndDeleteChaos(c, kubeCli, types.NamespacedName{Namespace: ns, Name: name}, kind, force); !ok {
		return
	}

	c.JSON(http.StatusOK, u.ResponseSuccess)
}

// @Summary Batch delete chaos experiments.
// @Description Batch delete chaos experiments by uids.
// @Tags experiments
// @Produce json
// @Param uids query string true "the experiment uids, split with comma. Example: ?uids=uid1,uid2"
// @Param force query string false "force" Enums(true, false)
// @Success 200 {object} utils.Response
// @Failure 400 {object} utils.APIError
// @Failure 404 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments [delete]
func (s *Service) batchDelete(c *gin.Context) {
	var (
		exp *core.Experiment
	)

	kubeCli, err := clientpool.ExtractTokenAndGetClient(c.Request.Header)
	if err != nil {
		u.SetAPIError(c, u.ErrBadRequest.WrapWithNoMessage(err))

		return
	}

	uids := c.Query("uids")
	if uids == "" {
		u.SetAPIError(c, u.ErrInternalServer.New("The uids cannot be empty"))

		return
	}

	uidSlice, force := strings.Split(uids, ","), c.DefaultQuery("force", "false")

	if len(uidSlice) > 100 {
		u.SetAPIError(c, u.ErrInternalServer.New("Too many uids, please delete less than 100 at a time"))

		return
	}

	for _, uid := range uidSlice {
		if exp, err = s.archive.FindByUID(context.Background(), uid); err != nil {
			if gorm.IsRecordNotFoundError(err) {
				u.SetAPIError(c, u.ErrNotFound.New("Experiment "+uid+" not found"))
			} else {
				u.SetAPIError(c, u.ErrInternalServer.WrapWithNoMessage(err))
			}

			return
		}

		ns, name, kind := exp.Namespace, exp.Name, exp.Kind
		if ok := checkAndDeleteChaos(c, kubeCli, types.NamespacedName{Namespace: ns, Name: name}, kind, force); !ok {
			return
		}
	}

	c.JSON(http.StatusOK, u.ResponseSuccess)
}

func checkAndDeleteChaos(c *gin.Context, kubeCli client.Client, namespacedName types.NamespacedName, kind string, force string) bool {
	var (
		chaosKind *v1alpha1.ChaosKind
		ok        bool
		err       error
	)

	if chaosKind, ok = v1alpha1.AllKinds()[kind]; !ok {
		u.SetAPIError(c, u.ErrBadRequest.New("Kind "+kind+" is not supported"))

		return false
	}

	ctx := context.Background()
	chaos := chaosKind.SpawnObject()

	if err = kubeCli.Get(ctx, namespacedName, chaos); err != nil {
		u.SetAPImachineryError(c, err)

		return false
	}

	if force == "true" {
		if err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			return forceClean(kubeCli, chaos)
		}); err != nil {
			u.SetAPIError(c, u.ErrInternalServer.New("Forced deletion failed"))

			return false
		}
	}

	if err := kubeCli.Delete(ctx, chaos); err != nil {
		u.SetAPImachineryError(c, err)

		return false
	}

	return true
}

func forceClean(kubeCli client.Client, chaos client.Object) error {
	annotations := chaos.(metav1.Object).GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	annotations[finalizers.AnnotationCleanFinalizer] = finalizers.AnnotationCleanFinalizerForced
	chaos.(metav1.Object).SetAnnotations(annotations)

	return kubeCli.Update(context.Background(), chaos)
}

// @Summary Pause a chaos experiment.
// @Description Pause a chaos experiment.
// @Tags experiments
// @Produce json
// @Param uid path string true "the experiment uid"
// @Success 200 {object} utils.Response
// @Failure 400 {object} utils.APIError
// @Failure 404 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments/pause/{uid} [put]
func (s *Service) pause(c *gin.Context) {
	var exp *core.Experiment

	kubeCli, err := clientpool.ExtractTokenAndGetClient(c.Request.Header)
	if err != nil {
		u.SetAPIError(c, u.ErrBadRequest.WrapWithNoMessage(err))

		return
	}

	uid := c.Param("uid")
	if exp, err = s.archive.FindByUID(context.Background(), uid); err != nil {
		if gorm.IsRecordNotFoundError(err) {
			u.SetAPIError(c, u.ErrNotFound.New("Experiment "+uid+" not found"))
		} else {
			u.SetAPIError(c, u.ErrInternalServer.WrapWithNoMessage(err))
		}

		return
	}

	annotations := map[string]string{
		v1alpha1.PauseAnnotationKey: "true",
	}
	if err = patchExperiment(kubeCli, exp, annotations); err != nil {
		u.SetAPImachineryError(c, err)

		return
	}

	c.JSON(http.StatusOK, u.ResponseSuccess)
}

// @Summary Start a chaos experiment.
// @Description Start a chaos experiment.
// @Tags experiments
// @Produce json
// @Param uid path string true "the experiment uid"
// @Success 200 {object} utils.Response
// @Failure 400 {object} utils.APIError
// @Failure 404 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments/start/{uid} [put]
func (s *Service) start(c *gin.Context) {
	var exp *core.Experiment

	kubeCli, err := clientpool.ExtractTokenAndGetClient(c.Request.Header)
	if err != nil {
		u.SetAPIError(c, u.ErrBadRequest.WrapWithNoMessage(err))

		return
	}

	uid := c.Param("uid")
	if exp, err = s.archive.FindByUID(context.Background(), uid); err != nil {
		if gorm.IsRecordNotFoundError(err) {
			u.SetAPIError(c, u.ErrNotFound.New("Experiment "+uid+" not found"))
		} else {
			u.SetAPIError(c, u.ErrInternalServer.WrapWithNoMessage(err))
		}

		return
	}

	annotations := map[string]string{
		v1alpha1.PauseAnnotationKey: "false",
	}
	if err = patchExperiment(kubeCli, exp, annotations); err != nil {
		u.SetAPImachineryError(c, err)

		return
	}

	c.JSON(http.StatusOK, u.ResponseSuccess)
}

func patchExperiment(kubeCli client.Client, exp *core.Experiment, annotations map[string]string) error {
	chaos := v1alpha1.AllKinds()[exp.Kind].SpawnObject()

	if err := kubeCli.Get(context.Background(), types.NamespacedName{Namespace: exp.Namespace, Name: exp.Name}, chaos); err != nil {
		return err
	}

	var mergePatch []byte
	mergePatch, _ = json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": annotations,
		},
	})

	return kubeCli.Patch(context.Background(), chaos, client.RawPatch(types.MergePatchType, mergePatch))
}

// @Summary Get the status of all experiments.
// @Description Get the status of all experiments.
// @Tags experiments
// @Produce json
// @Param namespace query string false "namespace"
// @Success 200 {object} status.AllChaosStatus
// @Failure 400 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments/state [get]
func (s *Service) state(c *gin.Context) {
	kubeCli, err := clientpool.ExtractTokenAndGetClient(c.Request.Header)
	if err != nil {
		u.SetAPIError(c, u.ErrBadRequest.WrapWithNoMessage(err))

		return
	}

	ns := c.Query("namespace")
	if ns == "" && !s.config.ClusterScoped && s.config.TargetNamespace != "" {
		ns = s.config.TargetNamespace

		log.V(1).Info("Replace query namespace with", ns)
	}

	allChaosStatus := status.AllChaosStatus{}

	g, ctx := errgroup.WithContext(context.Background())
	m := &sync.Mutex{}

	var listOptions []client.ListOption
	listOptions = append(listOptions, &client.ListOptions{Namespace: ns})

	for _, chaosKind := range v1alpha1.AllKinds() {
		list := chaosKind.SpawnList()

		g.Go(func() error {
			if err := kubeCli.List(ctx, list, listOptions...); err != nil {
				return err
			}
			m.Lock()

			for _, item := range list.GetItems() {
				s := status.GetChaosStatus(item.(v1alpha1.InnerObject))

				switch s {
				case status.Injecting:
					allChaosStatus.Injecting++
				case status.Running:
					allChaosStatus.Running++
				case status.Finished:
					allChaosStatus.Finished++
				case status.Paused:
					allChaosStatus.Paused++
				}
			}

			m.Unlock()
			return nil
		})
	}

	if err = g.Wait(); err != nil {
		u.SetAPImachineryError(c, err)

		return
	}

	c.JSON(http.StatusOK, allChaosStatus)
}

var upGrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Tail struct {
	Finished      bool
	conn          *websocket.Conn
	closed        chan bool
	namespace     string
	podNames      []string
	containerName string
	timestamps    bool

	enableLogName bool

	currentReqId string
	mu           sync.Mutex
}

type TailRequest struct {
	Id            string  `json:"id"`
	TailLines     *int64  `json:"tail_lines"`
	ContainerName *string `json:"container_name"`
	SinceTime     *time.Time
	Follow        bool
}

type LogMessageType string

const (
	LogMessageTypeReplace LogMessageType = "replace"
	LogMessageTypeAppend  LogMessageType = "append"
)

type logMessage struct {
	ReqId string         `json:"req_id"`
	Type  LogMessageType `json:"type"`
	Items []string       `json:"items"`
}

// NewTail creates new Tail object
func NewTail(conn *websocket.Conn, namespace string, podNames []string, containerName string, timestamps, enableLogName bool) *Tail {
	return &Tail{
		Finished:      false,
		conn:          conn,
		closed:        make(chan bool, 1),
		namespace:     namespace,
		podNames:      podNames,
		containerName: containerName,
		timestamps:    timestamps,
		enableLogName: enableLogName,
	}
}

func (t *Tail) Write(msg []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn.WriteMessage(websocket.TextMessage, msg)
}

// Start starts Pod log streaming
func (t *Tail) Start(ctx context.Context, clientset *kubernetes.Clientset) error {
	go func() {
		<-ctx.Done()
		t.closed <- true
	}()

	reqCh := make(chan *TailRequest, 1)

	errCh := make(chan error, 1)

	go func() {
		for {
			mt, p, err := t.conn.ReadMessage()

			if err != nil {
				errCh <- err
				return
			}

			if mt == websocket.CloseMessage || mt == -1 {
				t.closed <- true
				return
			}

			req := TailRequest{}
			err = json.Unmarshal(p, &req)

			if err != nil {
				logrus.Errorf("marshal tail msg: %s", err.Error())
				continue
			}

			reqCh <- &req
		}
	}()

	go func() {
		for {
			select {
			case <-t.closed:
				t.closed <- true
				break
			default:
			}

			req := <-reqCh
			t.currentReqId = req.Id

			logOptions := &v1.PodLogOptions{
				Container:  t.containerName,
				TailLines:  req.TailLines,
				Timestamps: t.timestamps,
			}

			if req.ContainerName != nil {
				logOptions.Container = *req.ContainerName
			}

			if req.SinceTime != nil {
				logOptions.SinceTime = &metav1.Time{
					Time: *req.SinceTime,
				}
			}

			now := time.Now()

			for _, podName := range t.podNames {
				podName := podName

				rs, err := clientset.CoreV1().Pods(t.namespace).GetLogs(podName, logOptions).Stream(ctx)
				if err != nil {
					errCh <- err
					return
				}

				err = func() error {
					defer rs.Close()
					buf := new(bytes.Buffer)
					_, err = io.Copy(buf, rs)
					if err != nil {
						return errors.Wrap(err, "error in copy information from podLogs to buf")
					}
					str := buf.String()
					lines := strings.Split(str, "\n")
					res := make([]string, 0, len(lines))
					for _, line := range lines {
						if t.enableLogName {
							line = fmt.Sprintf("[%s] [%s] %s", podName, t.containerName, line)
						}
						res = append(res, line)
					}
					msg := logMessage{
						ReqId: req.Id,
						Type:  LogMessageTypeReplace,
						Items: res,
					}
					msgStr, _ := json.Marshal(&msg)
					_ = t.Write(msgStr)
					if req.Follow {
						go func() {
							logOptions.Follow = true
							logOptions.TailLines = nil
							logOptions.SinceTime = &metav1.Time{
								Time: now,
							}
							rs, err := clientset.CoreV1().Pods(t.namespace).GetLogs(podName, logOptions).Stream(ctx)
							if err != nil {
								_, _ = fmt.Fprintln(os.Stderr, err)
								return
							}
							defer rs.Close()
							sc := bufio.NewScanner(rs)
							for sc.Scan() {
								select {
								case <-t.closed:
									t.closed <- true
									break
								default:
								}

								if t.currentReqId != req.Id {
									break
								}

								content := sc.Text()
								if t.enableLogName {
									content = fmt.Sprintf("[%s] [%s] %s", podName, t.containerName, content)
								}
								msg := logMessage{
									ReqId: req.Id,
									Type:  LogMessageTypeAppend,
									Items: []string{
										content,
									},
								}
								msgStr, _ := json.Marshal(&msg)
								_ = t.Write(msgStr)
							}
						}()
					}
					return nil
				}()
				if err != nil {
					errCh <- err
				}
			}
		}
	}()

	return <-errCh
}

// Finish finishes Pod log streaming with Pod completion
func (t *Tail) Finish() {
	t.Finished = true
}

// Delete finishes Pod log streaming with Pod deletion
func (t *Tail) Delete() {
	t.closed <- true
}

// @Summary Get the status of all experiments.
// @Description Get the status of all experiments.
// @Tags experiments
// @Produce json
// @Param namespace query string false "namespace"
// @Success 200 {object} status.AllChaosStatus
// @Failure 400 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments/state [get]
func (s *Service) watch(c *gin.Context) {
	var (
		exp *core.Experiment
	)

	var err error
	uid := c.Param("uid")
	if exp, err = s.archive.FindByUID(context.Background(), uid); err != nil {
		if gorm.IsRecordNotFoundError(err) {
			u.SetAPIError(c, u.ErrNotFound.New("Experiment "+uid+" not found"))
		} else {
			u.SetAPIError(c, u.ErrInternalServer.WrapWithNoMessage(err))
		}

		return
	}

	//ns, name, kind := exp.Namespace, exp.Name, exp.Kind
	ns := exp.Namespace
	//if chaosKind, ok := v1alpha1.AllKinds()[kind]; ok {
	//	conSelector = s.findChaosSelector(c, kubeCli, types.NamespacedName{Namespace: ns, Name: name}, chaosKind.SpawnObject())
	//} else {
	//	u.SetAPIError(c, u.ErrBadRequest.New("Kind "+kind+" is not supported"))
	//	return
	//}

	ws, err := upGrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		ws.WriteJSON(err)
		return
	}
	defer ws.Close()
	log.Info("upgrade websocket")

	var kubeConfigPath string
	if kubeConfigPath == "" {
		kubeConfigPath = os.Getenv("KUBECONFIG")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		ws.WriteJSON(err)
		return
	}

	cli, err := kubernetes.NewForConfig(config)
	if err != nil {
		ws.WriteJSON(err)
		return
	}
	log.Info("create cli, query pods", "ns", ns)
	podLists, err := cli.CoreV1().Pods(ns).List(c, metav1.ListOptions{LabelSelector: "app=redis-client"})
	if err != nil {
		ws.WriteJSON(err)
		return
	}
	log.Info("list pods", "len", len(podLists.Items))
	t := NewTail(ws, ns, []string{podLists.Items[0].Name}, "main", true, true)

	err = t.Start(c, cli)
	if err != nil {
		log.Info("tail failed", "err", err.Error())
	}
	return
}

// @Summary Get the status of all experiments.
// @Description Get the status of all experiments.
// @Tags experiments
// @Produce json
// @Param namespace query string false "namespace"
// @Success 200 {object} status.AllChaosStatus
// @Failure 400 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments/state [get]
func (s *Service) log(c *gin.Context) {
	var (
		exp *core.Experiment
		err error
	)

	header := c.Request.Header

	uid := c.Param("uid")
	if exp, err = s.archive.FindByUID(context.Background(), uid); err != nil {
		if gorm.IsRecordNotFoundError(err) {
			u.SetAPIError(c, u.ErrNotFound.New("Experiment "+uid+" not found"))
		} else {
			u.SetAPIError(c, u.ErrInternalServer.WrapWithNoMessage(err))
		}

		return
	}

	//ns, name, kind := exp.Namespace, exp.Name, exp.Kind
	ns := exp.Namespace

	data := map[string]interface{}{}
	err = json.Unmarshal([]byte(exp.Experiment), &data)
	if err != nil {
		return
	}

	spec, ok, err := unstructured.NestedMap(data, "spec", "selector", "labelSelectors")
	if !ok || err != nil {
		return
	}
	selector := map[string]string{}
	for k, v := range spec {
		selector[k] = fmt.Sprintf("%v", v)
	}
	cli, err := clientpool.ExtractTokenAndGetRestClient(header)
	if err != nil {
		return
	}

	podLists, err := cli.CoreV1().Pods(ns).List(c, metav1.ListOptions{LabelSelector: labels.FormatLabels(selector)})
	if err != nil {
		return
	}
	if len(podLists.Items) == 0 {
		return
	}
	pod := podLists.Items[0]
	var lines int64 = 50
	req := cli.CoreV1().Pods(ns).GetLogs(pod.Name, &v1.PodLogOptions{TailLines: &lines})
	podLogs, err := req.Stream(c)
	if err != nil {
		return
	}
	defer podLogs.Close()

	buf, err := ioutil.ReadAll(podLogs)
	if err != nil {
		return
	}

	c.Writer.Write(buf)
	return
}

// @Summary Get the status of all experiments.
// @Description Get the status of all experiments.
// @Tags experiments
// @Produce json
// @Param namespace query string false "namespace"
// @Success 200 {object} status.AllChaosStatus
// @Failure 400 {object} utils.APIError
// @Failure 500 {object} utils.APIError
// @Router /experiments/state [get]
func (s *Service) observeLocal(c *gin.Context) {
	handle, err := pcap.OpenOffline("/Users/joker/Desktop/tidb-hackathon-2021/dump-redis-simple.pcap")
	if err != nil {
		c.String(500, err.Error())
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []string
	for packet := range packetSource.Packets() {
		packets = append(packets, fmt.Sprintf("%s -> %s, \n%",
			packet.NetworkLayer().NetworkFlow().Src().String(),
			packet.NetworkLayer().NetworkFlow().Dst().String(),
			packet.String()))
	}
	c.JSON(0, obsStr{Tc: packets})
}

type obsTc struct {
	Src string
	Dst string
	TS  string
	Raw string
}

type obsStr struct {
	Tc   []string `json:"tc"`
	Func []string `json:"func"`
}

func (s *Service) upload(c *gin.Context) {
	c.Writer.Write([]byte("adsfhlkahdfllashfsd"))
}

func (s *Service) observe(c *gin.Context) {
	var (
		exp *core.Experiment
		err error
	)
	uid := c.Param("uid")
	if exp, err = s.archive.FindByUID(context.Background(), uid); err != nil {
		if gorm.IsRecordNotFoundError(err) {
			u.SetAPIError(c, u.ErrNotFound.New("Experiment "+uid+" not found"))
		} else {
			u.SetAPIError(c, u.ErrInternalServer.WrapWithNoMessage(err))
		}

		return
	}

	//ns, name, kind := exp.Namespace, exp.Name, exp.Kind
	ns := exp.Namespace

	data := map[string]interface{}{}
	err = json.Unmarshal([]byte(exp.Experiment), &data)
	if err != nil {
		return
	}

	spec, ok, err := unstructured.NestedMap(data, "spec", "selector", "labelSelectors")
	if !ok || err != nil {
		return
	}
	selector := map[string]string{}
	for k, v := range spec {
		selector[k] = fmt.Sprintf("%v", v)
	}
	cli, err := clientpool.ExtractTokenAndGetRestClient(c.Request.Header)
	if err != nil {
		return
	}

	podLists, err := cli.CoreV1().Pods(ns).List(c, metav1.ListOptions{LabelSelector: labels.FormatLabels(selector)})
	if err != nil {
		return
	}
	if len(podLists.Items) == 0 {
		return
	}
	pod := podLists.Items[0]

	daemonIP := "127.0.0.1"
	builder := grpcUtils.Builder(daemonIP, cconf.ControllerCfg.ChaosDaemonPort).WithDefaultTimeout()

	if cconf.ControllerCfg.TLSConfig.ChaosMeshCACert != "" {
		builder.TLSFromFile(cconf.ControllerCfg.TLSConfig.ChaosMeshCACert, cconf.ControllerCfg.TLSConfig.ChaosDaemonClientCert, cconf.ControllerCfg.TLSConfig.ChaosDaemonClientKey)
	} else {
		builder.Insecure()
	}
	cc, err := builder.Build()
	if err != nil {
		c.Writer.Write([]byte(err.Error()))
		return
	}
	containerId := pod.Status.ContainerStatuses[0].ContainerID
	resp, err := chaosdaemonclient.New(cc).CommonObserve(c, &pb.CommonObserveRequest{ContainerId: containerId})
	if err != nil {
		c.Writer.Write([]byte(err.Error()))
		return
	}
	c.JSON(0, resp)
	return
}
