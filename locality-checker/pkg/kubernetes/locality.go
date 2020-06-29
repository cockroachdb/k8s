package kubernetes

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type LocalityChecker struct {
	// The clientset for interacting with the Kubernetes API.
	Clientset kubernetes.Interface

	// The name of the Kubernetes node the container is running on.
	NodeName string

	// The directory to write locality information.
	WritePath string

	// Whether to error if node does not have region and zone labels.
	ErrorOnMissingLabels bool

	// A prefix to add to locality values. Useful for prepending the cloud provider's
	// name in front of the region and availability zone
	Prefix string
}

type localityInfo struct {
	Region string
	Zone   string
}

func (l *LocalityChecker) WriteLocality(ctx context.Context) error {
	localityInfo, err := l.getLocalityInfo(ctx)
	if err != nil {
		return err
	}
	if localityInfo == nil {
		return nil
	}
	return l.writeLocalityInfo(ctx, localityInfo)
}

func (l *LocalityChecker) getLocalityInfo(ctx context.Context) (*localityInfo, error) {
	labels, err := l.getNodeLabels(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "getting node labels failed")
	}
	region, err := l.getRegion(labels)
	if err != nil {
		if !l.ErrorOnMissingLabels {
			return nil, nil
		}
		return nil, errors.Wrap(err, "no region labels found")
	}
	zone, err := l.getZone(labels)
	if err != nil {
		if !l.ErrorOnMissingLabels {
			return nil, nil
		}
		return nil, errors.Wrap(err, "no zone labels found")
	}
	return &localityInfo{
		Region: l.Prefix + region,
		Zone:   l.Prefix + zone,
	}, nil
}

func (l *LocalityChecker) writeLocalityInfo(ctx context.Context, localityInfo *localityInfo) error {
	err := l.writeFile("region", localityInfo.Region)
	if err != nil {
		return err
	}
	err = l.writeFile("zone", localityInfo.Zone)
	if err != nil {
		return err
	}
	err = l.writeFile("locality", fmt.Sprintf(
		"--locality=region=%s,az=%s",
		localityInfo.Region,
		localityInfo.Zone,
	))
	if err != nil {
		return err
	}
	return nil
}

func (l *LocalityChecker) getNodeLabels(ctx context.Context) (map[string]string, error) {
	node, err := l.Clientset.CoreV1().Nodes().Get(ctx, l.NodeName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "node not found")
	}
	return node.GetObjectMeta().GetLabels(), nil
}

func (l *LocalityChecker) getRegion(labels map[string]string) (string, error) {
	return getFirstValue(labels, []string{
		"topology.kubernetes.io/region",
		"failure-domain.beta.kubernetes.io/region",
	})
}

func (l *LocalityChecker) getZone(labels map[string]string) (string, error) {
	return getFirstValue(labels, []string{
		"topology.kubernetes.io/zone",
		"failure-domain.beta.kubernetes.io/zone",
	})
}

func (l *LocalityChecker) writeFile(localityType string, localityValue string) error {
	return ioutil.WriteFile(fmt.Sprintf("%s/%s", l.WritePath, localityType), []byte(localityValue), 0644)
}

func getFirstValue(haystack map[string]string, needles []string) (string, error) {
	for _, needle := range needles {
		if value, ok := haystack[needle]; ok && value != "" {
			return value, nil
		}
	}
	return "", errors.New("value not found")
}
