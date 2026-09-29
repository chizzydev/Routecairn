{{- define "routecairn.name" -}}routecairn{{- end }}
{{- define "routecairn.fullname" -}}{{ .Release.Name }}-routecairn{{- end }}
{{- define "routecairn.serviceAccountName" -}}{{- if .Values.serviceAccount.create -}}{{ default (include "routecairn.fullname" .) .Values.serviceAccount.name }}{{- else -}}{{ required "serviceAccount.name is required when create=false" .Values.serviceAccount.name }}{{- end -}}{{- end }}
{{- define "routecairn.labels" -}}
app.kubernetes.io/name: {{ include "routecairn.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
