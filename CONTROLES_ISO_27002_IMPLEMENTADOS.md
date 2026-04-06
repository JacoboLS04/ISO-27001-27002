# Controles ISO/IEC 27002:2022 implementados en el proyecto

Documento actualizado con el estado real de implementacion, incluyendo monitoreo avanzado, deteccion activa de anomalias y stack de observabilidad con contenedores.

## Alcance

- Backend: Spring Boot (seguridad, auditoria, metricas, deteccion de anomalias).
- Frontend: React (autenticacion, controles por rol, telemetria de errores y eventos sospechosos).
- Observabilidad: Prometheus + Grafana + Alertmanager + integracion SIEM (Wazuh).

---

## Control 8.15 - Registro de eventos (Logging)

### Objetivo del control
Producir, almacenar, proteger y analizar registros de actividades, excepciones y fallas para generar evidencia, detectar incidentes y proteger la integridad de los logs.

### Implementado en Backend

1. Produccion y almacenamiento de logs de seguridad
- Se registra actividad relevante de autenticacion y administracion:
  - LOGIN_SUCCESS
  - LOGIN_FAILED
  - ACCOUNT_LOCKED
  - USER_REGISTERED
  - USER_DELETED
  - RECAPTCHA_FAILED
  - STEP_UP
  - AUDIT_EVENT
  - eventos de anomalia (ejemplo: ANOMALY_401_SPIKE)
- Configuracion de logback con archivo local y rotacion diaria.
- Conservacion historica configurada en rolling policy.

2. Campos de evidencia registrados
- Usuario involucrado (username)
- Tipo de evento
- Estado del evento (SUCCESS, FAILED, ALERT)
- Fecha y hora UTC
- Detalles del evento
- Metadatos adicionales cuando aplica (ip, userAgent, stack, url, timestamp cliente)

3. Proteccion e integridad operativa
- Emision de eventos centralizada en servicio de auditoria para evitar dispersion.
- Opcion de forwarding a SIEM por HTTP con firma HMAC.
- Recomendacion documentada de hardening del sistema operativo y permisos de archivos de log.

4. Analisis de logs
- Servicio de analisis de logs con resumen, clasificacion por tipo/usuario y score de riesgo.
- Endpoint de analisis disponible para rol administrativo.

### Implementado en Frontend

1. Visualizacion de auditoria para perfil admin
- Dashboard consume endpoint de analisis y muestra total de eventos, exitos/fallos, riesgo y eventos recientes.

2. Evidencia operativa
- Tarjetas de riesgo y tabla de eventos para revision y trazabilidad.

### Estado y brechas

- Implementado: generacion, almacenamiento, consumo y analisis.
- Parcial: integridad fuerte depende tambien de controles de infraestructura (permisos, backup inmutable, WORM si aplica).
- Recomendado: retencion central en SIEM y controles de acceso de solo lectura para operadores.

---

## Control 8.16 - Monitoreo de actividades

### Objetivo del control
Monitorear redes, sistemas y aplicaciones para detectar comportamientos anormales de forma oportuna.

### Implementado en Backend

1. Telemetria y metricas operativas
- Integracion de Spring Boot Actuator.
- Endpoints expuestos para health, metrics y prometheus.
- Integracion de Micrometer + Prometheus registry.

2. Metricas de seguridad personalizadas
- security_auth_login_success_total
- security_auth_login_failed_total
- security_auth_login_locked_total
- security_http_401_total
- security_frontend_js_errors_total
- security_frontend_unhandled_rejections_total
- security_frontend_csp_violations_total
- security_frontend_script_injection_suspected_total
- security_frontend_api_failure_spikes_total
- security_anomaly_alerts_total

3. Metricas derivadas por ventana temporal
- security_auth_login_failed_last_10m
- security_http_401_last_5m
- security_frontend_errors_last_10m

4. Deteccion activa de anomalias en aplicacion
- Servicio programado que escanea patrones de riesgo cada ventana configurable.
- Umbrales configurables por propiedad (401, login failed, frontend errors).
- Cooldown para evitar duplicacion excesiva de alertas.
- Publicacion de eventos de anomalia en auditoria (estado ALERT).

5. Ingesta de eventos de frontend
- Endpoint publico de monitoreo de eventos frontend.
- Sanitizacion de campos para reducir riesgo de inyeccion en observabilidad.

### Implementado en Frontend

1. Telemetria de errores y seguridad
- Captura de errores JS globales.
- Captura de unhandled promise rejections.
- Captura de CSP violations.

2. Deteccion adicional de comportamiento sospechoso
- Deteccion de inyeccion de scripts sospechosos en DOM (MutationObserver).
- Deteccion de burst de errores frontend por ventana de tiempo.
- Deteccion de picos de fallos API en cliente.

3. Envio robusto de eventos
- Envio con sendBeacon/fallback fetch para no interrumpir UX.

### Alertas implementadas

1. Reglas de Prometheus
- BruteForceSuspected
- LoginFailuresSpike
- HighJvmMemoryPressure
- HighCpuUsage
- FrontendErrorsSpike
- SuspiciousScriptInjection
- ApiFailureSpike
- PossibleDdosPattern
- BackendAnomalyDetectorTriggered

2. Alertmanager
- Ruteo por severidad.
- Receiver default y receiver high-priority.
- Inhibit rules para suprimir alertas medias cuando existe critica equivalente.

3. Dashboard Grafana
- Dashboard importable para Control 8.16 con KPIs, series de seguridad y capacidad.

### Estado y brechas

- Implementado: monitoreo tecnico + seguridad + deteccion activa + alertado.
- Pendiente operativo: conectar receiver de Alertmanager a canal real (email/Slack/Teams/webhook productivo).
- Recomendado: calibrar umbrales en ambiente real para minimizar falsos positivos.

---

## Control 8.5 - Autenticacion segura

### Objetivo del control
Asegurar que solo entidades autorizadas accedan, con mecanismos proporcionales al riesgo.

### Implementado en Backend

1. Autenticacion y sesion
- Login con credenciales y emision de JWT.
- Password hashing con BCrypt.
- Validacion de politica minima de contrasena en registro.

2. Proteccion contra fuerza bruta
- Bloqueo temporal por intentos fallidos consecutivos.
- Registro de intentos fallidos y eventos de bloqueo.

3. CAPTCHA
- Verificacion de reCAPTCHA en backend para login y registro.

4. Mensajeria segura
- Errores de login genericos para no revelar existencia de cuenta.

### Implementado en Frontend

1. Integracion de reCAPTCHA en login/registro
- Obtencion y envio del token al backend.

2. UX de seguridad
- Validaciones de contrasena y confirmacion.

### Estado y brechas

- Implementado: autenticacion robusta con controles anti abuso.
- Brecha relevante: MFA aun no implementado para perfiles de alto riesgo.

---

## Control 8.2 - Derechos de acceso privilegiado

### Objetivo del control
Restringir y gestionar permisos elevados bajo minimo privilegio y control temporal.

### Implementado en Backend

1. RBAC y autorizacion por rol
- Endpoints criticos restringidos a ROLE_ADMIN.
- Validacion por reglas de seguridad y autorizacion por metodo.

2. Step-up authentication para acciones criticas
- Reautenticacion requerida para operaciones sensibles.
- Token de elevacion temporal con TTL corto.

3. Restricciones de cuentas genericas
- Bloqueo de nombres de usuario genericos o sensibles.

4. Evidencia administrativa
- Eventos de step-up y operaciones privilegiadas quedan en auditoria.

### Implementado en Frontend

1. Flujo privilegiado con step-up
- Solicitud de credencial adicional antes de accion critica.

2. UI por rol
- Secciones administrativas visibles y operables solo para rol admin.

### Estado y brechas

- Implementado: control por rol + step-up + trazabilidad.
- Recomendado: separacion operativa de cuentas admin para tareas no privilegiadas.

---

## Componentes y artefactos clave (actualizado)

1. Observabilidad y alertado
- monitoring/prometheus.yml
- monitoring/prometheus-alert-rules.yml
- monitoring/alertmanager.yml
- monitoring/grafana-dashboard-iso-8-16.json
- docker-compose.yml (prometheus, alertmanager, grafana)

2. Backend de monitoreo
- servicio de metricas personalizadas
- servicio de deteccion de anomalias programado
- endpoint de ingesta de eventos frontend

3. Frontend de monitoreo
- modulo de captura de errores, CSP, inyeccion sospechosa y picos de fallos API

---

## Recomendaciones transversales (produccion)

1. HTTPS estricto
- Forzar TLS extremo a extremo y redireccion HTTP a HTTPS.
- Habilitar HSTS en ambiente productivo.

2. Cadena completa de deteccion y respuesta
- Prometheus + Alertmanager + Grafana en operacion continua.
- Wazuh activo para correlacion SIEM y evidencia forense centralizada.

3. Evidencia para auditoria
- Capturas de dashboard y alertas firing.
- Registro de pruebas de activacion de alertas.
- Bitacora de tuning de umbrales y respuesta a incidentes.
