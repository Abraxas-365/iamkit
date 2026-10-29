{{- define "iamkit.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "iamkit.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "iamkit.selectorLabels" -}}
app.kubernetes.io/name: {{ include "iamkit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "iamkit.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "iamkit.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "iamkit.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "iamkit.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "iamkit.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "iamkit.issuer" -}}
{{- required "issuer is required (the public HTTPS origin)" .Values.issuer | trimSuffix "/" -}}
{{- end -}}

{{/*
The most replicas the release can run: the HPA ceiling, else replicaCount.
More than one needs the shared Redis (rate limits, usage windows, metadata
caches and refetch throttles are per process without it): the chart refuses
to render otherwise, and the pods get IAMKIT_REPLICAS so the server refuses
to start the same way.
*/}}
{{- define "iamkit.replicas" -}}
{{- $n := int (ternary .Values.autoscaling.maxReplicas .Values.replicaCount .Values.autoscaling.enabled) -}}
{{- if and (gt $n 1) (not .Values.redis.existingSecret) -}}
{{- fail (printf "up to %d replicas need Redis: set redis.existingSecret (a Secret holding REDIS_URL), or run one replica (replicaCount: 1, autoscaling.enabled: false). Without a shared Redis every replica keeps its own rate limits, caches and throttles" $n) -}}
{{- end -}}
{{- $n -}}
{{- end -}}

{{- define "iamkit.geoipDir" -}}
/geoip
{{- end -}}

{{- define "iamkit.geoipDatabase" -}}
{{ include "iamkit.geoipDir" . }}/{{ .Values.geoip.editionId }}.mmdb
{{- end -}}

{{/* Environment shared by the server and the migration Job. */}}
{{- define "iamkit.databaseEnv" -}}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ required "database.existingSecret is required" .Values.database.existingSecret }}
      key: {{ .Values.database.key }}
{{- end -}}

{{- define "iamkit.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 100
runAsGroup: 101
fsGroup: 101
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "iamkit.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}
