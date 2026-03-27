package validators

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// DenyUnconfinedSeccomp is a Validator that denies usage of Unconfined Seccomp profile
type DenyUnconfinedSeccomp struct{}

var _ Validator = DenyUnconfinedSeccomp{}

func (v DenyUnconfinedSeccomp) Validate(ctx context.Context, pod *corev1.Pod) field.ErrorList {
	p := field.NewPath("spec")
	var errs field.ErrorList

	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
		if !isValidSeccomp(pod.Spec.SecurityContext.SeccompProfile.Type) {
			errs = append(errs,
				field.Forbidden(
					p.Child("securityContext", "seccompProfile", "type"),
					fmt.Sprintf("%s is not an allowed seccomp profile", pod.Spec.SecurityContext.SeccompProfile.Type),
				),
			)
		}
	}

	visitContainers(&pod.Spec, p, func(container *corev1.Container, path *field.Path) {
		if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
			if !isValidSeccomp(container.SecurityContext.SeccompProfile.Type) {
				errs = append(errs,
					field.Forbidden(
						path.Child("securityContext", "seccompProfile", "type"),
						fmt.Sprintf("%s is not an allowed seccomp profile", container.SecurityContext.SeccompProfile.Type),
					),
				)
			}
		}
	})

	return errs
}

func isValidSeccomp(t corev1.SeccompProfileType) bool {
	return t == corev1.SeccompProfileTypeLocalhost ||
		t == corev1.SeccompProfileTypeRuntimeDefault
}

// containerVisitor is called with each container and its field path.
type containerVisitor func(container *corev1.Container, path *field.Path)

// visitContainers invokes the visitor function for every container in the given pod spec.
func visitContainers(podSpec *corev1.PodSpec, specPath *field.Path, visitor containerVisitor) {
	initContainersPath := specPath.Child("initContainers")
	for i := range podSpec.InitContainers {
		visitor(&podSpec.InitContainers[i], initContainersPath.Index(i))
	}

	containersPath := specPath.Child("containers")
	for i := range podSpec.Containers {
		visitor(&podSpec.Containers[i], containersPath.Index(i))
	}

	ephemeralContainersPath := specPath.Child("ephemeralContainers")
	for i := range podSpec.EphemeralContainers {
		visitor(
			(*corev1.Container)(&podSpec.EphemeralContainers[i].EphemeralContainerCommon),
			ephemeralContainersPath.Index(i),
		)
	}
}
