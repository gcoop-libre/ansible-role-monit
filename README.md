Monit
=====

An Ansible Role that configures [Monit](https://mmonit.com/monit/) on the target host on Debian / Ubuntu.

Requirements
------------

None.

Role Variables
--------------

Available variables are listed below, along with default values (see `defaults/main.yml`):

    monit_conf_dir: /etc/monit
    monit_lib_dir: /var/lib/monit

Base directories where `Monit` configurations and files will be created.

    monit_interval: 120

Interval (in seconds) between monitoring cycles.

    monit_start_delay: 0

The start delay option can be used to wait (once) before Monit starts checking services.

    monit_log: /var/log/monit.log

Path for the `Monit` logs.

    monit_pid: ''

Path for the `Monit` PID file.

    monit_limits:
      program_output:
        value: 512
        unit: B
      send_expect_buffer:
        value: 256
        unit: B
      file_content_buffer:
        value: 512
        unit: B
      http_content_buffer:
        value: 1
        unit: MB
      network_timeout:
        value: 5
        unit: seconds
      program_timeout:
        value: 300
        unit: seconds
      stop_timeout:
        value: 30
        unit: seconds
      start_timeout:
        value: 30
        unit: seconds
      restart_timeout:
        value: 30
        unit: seconds

This property configure and set various limits to tweak buffer sizes and timeouts used by Monit. The available options are:

* `program_output`: limit for check program output (truncated after)
* `send_expect_buffer`: limit for send/expect protocol test
* `file_content_buffer`: limit for file content test (line)
* `http_content_buffer`: limit for HTTP content test (response body)
* `network_timeout`: timeout for network I/O
* `program_timeout`: timeout for check program
* `stop_timeout`: timeout for service stop
* `start_timeout`: timeout for service start
* `restart_timeout`: timeout for service restart

Depending on your `Monit` version, some of them may not be available, but the role tries to generate a valid config file.

    monit_ssl:
      version: tlsv12
      verify: True
      selfsigned: False
      ciphers: ''
      httpd_pem: /etc/monit/ssl/httpd.pem
      client_pem: /etc/monit/ssl/clients.pem
      ca_pem: /etc/monit/ssl/ca.pem
      ca_dir: /usr/share/ca-certificates

SSL/TLS options for all SSL connections made through `Monit`. On current versions of `Monit` they can be overrided on the mail config, httpd interface and tests. The available options are:

* `version`: the specific SSL/TLS version to use. By default `Monit` uses `auto`. In `auto` mode, only TLS is used, SSLv2 and SSLv3 is considered obsolete. If you have to use SSLv2 or SSLv3, you must explicitly set the version. Available options are: `auto`, `sslv2`, `sslv3`, `tlsv1`, `tlsv11`, `tlsv12`.
* `verify`: enables SSL server certificate verification. This will verify and report an error if the server certificate is not trusted, not valid or has expired.
* `selfsigned`: Use this option to allow self-signed certificates.
* `ciphers`: override default SSL/TLS ciphers.
* `pemfile`: set the path to the SSL server certificate "database-file" in PEM format. This options has effect only for the monit HTTPD interface.
* `clientpemfile`: set the path to the PEM encoded SSL client certificates database file. If set, a client certificate authentication is enabled.
* `cacertificatefile`: set the path to the PEM encoded file containing Certificate Authority (CA) certificates. `Monit` uses OpenSSL's default CA certificates if this options is not used.
* `cacertificatepath`: set the path to the directory containing Certificate Authority (CA) certificates. `Monit` uses OpenSSL's default CA certificates if this options is not used.

Depending on your `Monit` version, some of them may not be available, but the role tries to generate a valid config file.

    monit_queue_events: True

Enable the use of a queue for the events alerts if the mail server is temporarily unavailable.

    monit_queue_slots: 100

Limit the number of event messages in the queue.

    monit_mmonit: False
    monit_mmonit_ssl: True
    monit_mmonit_host: 192.168.1.10
    monit_mmonit_port: 8443
    monit_mmonit_user: monit
    monit_mmonit_password: monit
    monit_mmonit_uri: /collector
    monit_mmonit_timeout: 0
    monit_mmonit_credentials: True

Properties for [M/Monit](https://mmonit.com/) configuration.

    monit_httpd: True

Enables HTTP suport on `Monit` daemon.

    monit_httpd_unixsocket: ''

Path for the Unix Socket of `Monit` HTTP interface. This disable the TCP interface.

    monit_httpd_port: 2812

Port where `Monit` should bind to and listen on.

    monit_httpd_address: 127.0.0.1

IP address where `Monit` should listen. If no value is specified, `Monit` will listen on all available interfaces.

    monit_httpd_signature: False

Enable version from the HTTP response header and error pages.

    monit_httpd_ssl: True

Enable the use of SSL for the HTTP interface.

    monit_httpd_ssl_options:
      version: tlsv12
      verify: True
      selfsigned: False
      ciphers: ''
      httpd_pem: /etc/monit/ssl/httpd.pem
      client_pem: /etc/monit/ssl/clients.pem
      ca_pem: /etc/monit/ssl/ca.pem
      ca_dir: /usr/share/ca-certificates

This property allows overriding the global SSL configuration for the HTTP interface.

    monit_httpd_acl:
      - host: localhost
        readonly: False
      - user: admin
        password: monit
        readonly: False
      - group: monit
        readonly: False

Restrict access to the `Monit` HTTP interface. At least one access rule should be allowed. The `readonly` option restrict the access only for checking for service statuses.

    monit_mail: False

Enable the use of a mail server for sending alerts.

    monit_mail_host: localhost
    monit_mail_port: 25

Host and port of the SMTP server.

    monit_mail_user: ''
    monit_mail_password: ''

User and password for the SMTP server.

    monit_mail_ssl: False

Enable the use of SSL connections to the SMTP server.

    monit_mail_ssl_options:
      version: tlsv12
      verify: True
      selfsigned: False
      ciphers: ''
      client_pem: /etc/monit/ssl/clients.pem
      ca_pem: /etc/monit/ssl/ca.pem
      ca_dir: /usr/share/ca-certificates

This property allows overriding the global SSL configuration for the SMTP server.

    monit_mail_timeout: 5

Timeout for the connection.

    monit_mail_hostname: ''

By default, `Monit` uses the local host name in SMTP HELO/EHLO and in the Message-ID header. You can override this using this property.

    monit_mail_format:
      from: monit@foo.bar
      reply-to: support@domain.com
      subject: $SERVICE $EVENT at $DATE
      message: |
        Monit $ACTION $SERVICE at $DATE on $HOST: $DESCRIPTION.
        Yours sincerely,
        monit

Global configuration for the mail sended by alerts. Only needed options may be included. The available options are:

* `from`: set the sender's email address.
* `reply-to`: set the reply-to mail header.
* `subject`: set the message subject.
* `message`: set the mail body.

The subject and body may contain some variables, which are expanded by `Monit`. Here is a list of variables that can be used when composing an alert message:

* `$EVENT`: A string describing the event that occurred.
* `$SERVICE`: The service name
* `$DATE`: The current time and date (RFC 822 date style).
* `$HOST`: The name of the host Monit is running on
* `$ACTION`: The name of the action which was done by Monit.
* `$DESCRIPTION`: The description of the error condition

    monit_alerts:
      - email: email@domain.com
        events: []
        reminder: 5
        mail_format:
          from: monit@foo.bar
          reply-to: support@domain.com
          subject: $SERVICE $EVENT at $DATE
          message: |
            Monit $ACTION $SERVICE at $DATE on $HOST: $DESCRIPTION.
            Yours sincerely,
            monit

List of global recipients for the alerts. This could be modified by service basis. Each alert should have an `email`, it may list the `events` for which to send the alert and it may set the number of cycles to send a `reminder`. Finally, it may override any of the options of the global `mail_format`.

    monit_monitors: []

List of services to monitor. Each one of them should be a dictionary using the following keys to set they properties:

    name: sshd

Name of the service that would be monitored. It should be unique and would be used for the file where the tests for the service are defined.

    enabled: True

This property allows temporarily disabling a service without deleting it's configuration.

    monitor_process: False

Set the service as a check over a [process](https://mmonit.com/monit/documentation/#Process).

    monitor_file: False

Set the service as a check over a [file](https://mmonit.com/monit/documentation/#File).

    monitor_fifo: False

Set the service as a check over a [FIFO](https://mmonit.com/monit/documentation/#Fifo).

    monitor_filesystem: False

Set the service as a check over a [filesystem](https://mmonit.com/monit/documentation/#Filesystem).

    monitor_directory: False

Set the service as a check over a [directory](https://mmonit.com/monit/documentation/#Directory).

    monitor_host: False

Set the service as a check over a [remote host](https://mmonit.com/monit/documentation/#Remote-host).

    monitor_system: False

Set the service as a check over the local [system](https://mmonit.com/monit/documentation/#System).

    monitor_program: False

Set the service as a check over an executable [program](https://mmonit.com/monit/documentation/#Program).

    monitor_network: False

Set the service as a check over a [network interface](https://mmonit.com/monit/documentation/#Network).

    pid: /var/run/sshd.pid
    regex: ssh

The `process` check should be executed over a `pid`file or using a `regex` to match the process name.

    path: /etc/init.d/ssh

This property defines the path to check for the `file`, `fifo`, `filesystem` and `directory` checks. It also defined the path for the `program` to be executed.

    host: 192.168.10.10

This property defines the IP address of the `remote host` that should be checked.

    uid: monit
    gid: monit

User and group that `Monit` should use when running the `program` check.

    timeout: 30

Timeout for the execution of the `program` checks.

    address: 192.168.10.1
    interface: eth0

IP `address` or `interface` name of the `network interface` to check.

    start:
      command: /etc/init.d/ssh start
      uid: monit
      gid: monit
      timeout: 5

Command to execute on `start` action. If it should run with a user or group different of the used by `Monit`, they can be specified with `uid` and `gid`. `timeout` may also be defined here.

    stop:
      command: /etc/init.d/ssh stop
      uid: monit
      gid: monit
      timeout: 5

Command to execute on `stop` action. If it should run with a user or group different of the used by `Monit`, they can be specified with `uid` and `gid`. `timeout` may also be defined here.

    restart:
      command: /etc/init.d/ssh restart
      uid: monit
      gid: monit
      timeout: 5
      limit:
        number: 2
        cycles: 5
        action_alert: True
        action_restart: False
        action_start: False
        action_stop: False
        action_exec:
          command: "/usr/local/bin/sms.sh"
          uid: monit
          gid: monit
          repeat: 5
        action_unmonitor: False

Command to execute on `restart` action. If it should run with a user or group different of the used by `Monit`, they can be specified with `uid` and `gid`. `timeout` may also be defined here. The number of consecutive restart may be limited using the `limit` dictionary, setting the `number` of restarts in how many `cycles` and the `action` to executes when the limit is reached.

    every_cycles: 5
    every_cron: "* 8-19 * * 1-5"
    not_every_cron: "* 0-3 * * 0"

The service poll time is handled with this 3 properties. If one of them is defined, the service is checked every X cycles or using a cron definition.

    groups:
      - www

With this property it is possible to group similar service entries together and manage them as a whole. Every service may have more than one group assigned.

    mode_active: True

In active mode, `Monit` will pro-actively monitor a service and in case of problems raise alerts and restart the service. Active is the default mode.

    onreboot_start: True
    onreboot_nostart: False
    onreboot_laststate: False

* In `start` mode, `Monit` will always start the service automatically on reboot, even if it was stopped before restart.
* In `nostart` mode, the service is never started automatically after reboot.
* In `laststate` mode, a service's monitoring state is persistent across reboot. For instance, if a service was started before reboot, it willl be started after reboot. If it was stopped before reboot, it will not be started after and so on.

    depends:
      - sshd_rc

This property defines the list of dependencies of the service. `Monit` can do dependency checking before start, stop, monitoring or unmonitoring of services.

    tests: []

List of tests to be executed to the service. Each test is a dictionary composed by, at least, a type of test and an action. It may include a succeeded action as well and set a fault tolerance, so a test should fail more than once to execute the defined action.

    ignore_content:
      - match: True
        regex: .*
        path: /etc/monit/regexfile

The lines matching the rules defined in this property are not inspected during the execution of an `content` tests. With `match` the line is excluded when it matches or not the defined `regex` or the regular expressions defined in the `path` file.

    alerts:
      - email: email@domain.com
        events: []
        reminder: 5
        mail_format:
          from: monit@foo.bar
          reply-to: support@domain.com
          subject: $SERVICE $EVENT at $DATE
          message: |
            Monit $ACTION $SERVICE at $DATE on $HOST: $DESCRIPTION.
            Yours sincerely,
            monit

List of local recipients for the alerts generated by the tests of the service. This recipients are add to the global recipients. Each alert should have an `email`, it may list the `events` for which to send the alert and it may set the number of cycles to send a `reminder`. Finally, it may override any of the options of the global `mail_format`.

    noalert:
      - email@domain.com

List of global alert recipients that should not receive the alerts of this service.

## Tests

Each item of the `tests` list should use one of the following tests, tacking care that it could be used with the selected check type.

    test_existence:
      exist: True

This test allows to trigger an action based on the monitored object existence. It is supported for `process`, `file`, `directory`, `filesystem` and `fifo` services.

    test_load:
      interval_1min: True
      interval_5min: False
      interval_15min: False
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10

This test allows to trigger an action based on the `system`'s load average. `interval_1min`, `interval_5min` and `interval_15min` defines the time period to average the number of processes in the system queue. This number can be `greater`, `less`, `equal` or `notequal` to the specified `value`.

    test_cpu:
      user: False
      system: False
      wait: False
      total: False
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10

This test allows to trigger an action based on the percent of time the system spend in user or kernel space and I/O. The `user` / `system` / `wait` properties are optional, if not used, the total system cpu usage is tested. 

In the case of a `process`, this test allows to trigger an action based on the CPU usage of the process itself. The process children may be included if the `total` property is used.

    test_threads:
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10

This test allows to trigger an action based on the number of threads of the `process`.

    test_children:
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10

This test allows to trigger an action based on the number of children of the `process`.

    test_memory:
      total: False
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10
      unit: B

This test allows to trigger an action based on the `system` memory usage. The `unit` can be percent `%` or an absolute value [`B`, `kB`, `MB`, `GB`].

In the case of a `process`, this test allows to trigger an action based on the memory usage of the memory itself. The process children may be included if the `total` property is used.

    test_swap:
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10
      unit: B

This test allows to trigger an action based on the `system` swap usage. The `unit` can be percent `%` or an absolute value [`B`, `kB`, `MB`, `GB`].

    test_io:
      read: True
      operations: False
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10
      unit: B

This test allows to trigger an action based on the read and write activity of a `process` or a `filesystem`. `read` defines which operation to test. The `unit` can be percent `%` or an absolute value [`B`, `kB`, `MB`, `GB`].

In the case of a `filesystem`, this test allows to trigger an action based on the number of `operations` readed of writed per second.

    test_checksum:
      changed: True
      failed: False
      sha1: True
      md5: False
      expected: cf32be630596d2ceff8582566d94b6eb5263191a

This test allows to trigger an action based on the `file`'s MD5 or SHA1 checksum. The action can be triggered when the value of the checksum `changed` or when it `failed` to check the `expected` value.

    test_timestamp:
      changed: True
      access: False
      modification: False
      change: False
      older: True
      newer: False
      greater: False
      less: False
      equal: False
      notequal: False
      value: 10
      unit: seconds

This test allows to trigger an action based on the timestamp of the `file`, `fifo` or the `directory`. This test can compare the `access`, `modification` or `change` timestamp to verify if it is `older`, `newer`, `greater`, `less`, `equal` or `notequal` than the `value` measured in `unit`s.

Also the test can be triggered if the timestamp has `changed`.

    test_size:
      changed: True
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10
      unit: B

This test allows to trigger an action based on the size of the `file`. Also the test can be triggered if the size has `changed`.

    test_content:
      match: True
      regex: .*
      path: /etc/monit/regexfile

This test allows to trigger an action based on the content of a _text_ `file`. The file is incrementally analyzed to `match` or not the `regex` or regular expressions defined in the `path` file.

    test_mount_flags: False

This test allows to trigger an action based on a change of the mount flags of a `filesystem`.

    test_usage:
      inodes: False
      free: False
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10
      unit: %
      percent: False

This test allows to trigger an action based on the usage of space or `inodes` of a `filesystem` or disk. Also the test can verify the `free` spaces or inodes.

In the case the test verify the amount of used / free inodes, the value can be absolute or a `percent` of the total amount.

    test_service_time:
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10

This test allows to trigger an action based on the time taken to complete a read or a write operation. This test can be used only on `filesystem` services.

    test_permissions:
      changed: True
      mode: ''

This test allows to trigger an action based on the permissions of a `file`, `fifo`, `directory` or `filesystem` service. It can verify if the permissions has `changed` or if the are a particular octal `mode`.

    test_uid: monit

This test allows to trigger an action based on owner user of a `file`, `fifo`, `directory` or `process`.

    test_gid: monit

This test allows to trigger an action based on owner group of a `file`, `fifo`, `directory` or `process`.

    test_pid: False

This test allows to trigger an action based on the `process`' PID.

    test_ppid: False

This test allows to trigger an action based on the `process`' parent PID.

    test_uptime:
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10
      unit: hours

This test allows to trigger an action based on the uptime of the `system` or a particular `process`. The `unit` of the time can be measured in `days`, `hours`, `minutes` or `seconds`.

    test_status:
      changed: True
      greater: True
      less: False
      equal: False
      notequal: False
      value: 0

This test allows to trigger an action based on the exit status of an executable `program` or script. The test can compare the status with a partiular `value` or it can verify if the status has `changed`.

    test_link:
      status: True
      capacity: False

This test allows to trigger an action based on the status of a `network` interface link or it's `capacity`.

    test_saturation:
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10

This test allows to trigger an action based on the `network`'s saturation. `Monit` then computes the link utilisation based on the current transfer rate vs. link capacity.

    test_bandwidth:
      upload: True
      download: False
      greater: True
      less: False
      equal: False
      notequal: False
      value: 10
      packets: False
      unit: GB
      interval:
        value: 12
        unit: hours

This test allows to trigger an action based on the `network` interface `upload` or `download` bandwidth usage, current transfer speed or the total data transferred in the specified `interval`. The current transfer speed and the total data can also be measured in `packets`.

    test_ping:
      ipv4: False
      ipv6: False
      count: 3
      size: 64
      timeout: 5
      address: 192.168.10.1

This test allows to trigger an action based on the PING response of the `host`. You can force Monit to only ping `ipv4` or `ipv6` addresses. The `count` property specifies how many consecutive ping requests will be sent to the host in one cycle at maximum. The `size` property specifies the ping request data size. If no reply arrive within `timeout` seconds, `Monit` reports an error. The `address` property specifies the source IP address.

    test_connection:
      host: 191.168.10.10
      port: 22
      ipv4: False
      ipv6: False
      address: 192.168.10.1
      socket: /var/run/socket.sock
      tcp: False
      udp: False
      ssl: False
      ssl_options:
        version: tlsv12
        verify: True
        selfsigned: False
        ciphers: ''
        client_pem: /etc/monit/ssl/clients.pem
        ca_pem: /etc/monit/ssl/ca.pem
        ca_dir: /usr/share/ca-certificates
      certificate_checksum:
        sha1: True
        md5: False
        expected: cf32be630596d2ceff8582566d94b6eb5263191a
      certificate_valid: 30
      protocol: ssh
      send_expect:
        - value: '\0xFF\0xFF\0xFF\0xFFgetstatus'
          send: False
          expect: False
      timeout: 5
      retry: 2
      username: monit
      password: s3Cr3T
      uri: /custom-uri
      method_get: False
      method_head: False
      response_code: 404
      checksum:
        sha1: True
        md5: False
        expected: cf32be630596d2ceff8582566d94b6eb5263191a
      headers: {}
      content: '<a href="foo">bar</a>'
      properties:
        name: loglimit
        greater: True
        less: False
        equal: False
        value: 10
      target: valid@uri
      max_forward: 6
      origin: http://websocket.com
      version: 13
      identity: ~/.ssh/id_rsa
      command: pwd

This test allows to trigger an action based on a failed connection via a network ports or via Unix sockets. A connection test may only be used within a `process` or `host` service type context. This test has many option, according to the selected protocol.

* `host`: Optionally specify the host to connect to. If the host is not given then localhost is assumed if this test is used inside a process entry. If this test is used inside a remote host entry then the entry's remote host is assumed. When using `varnish_backend` protocol, the host should contain the backend name which status will be tested.
* `port`: The port number to connect to.
* `ipv4`: Optionally specify `Monit` should use IPv4 when trying to connect to the port.
* `ipv6`: Optionally specify `Monit` should use IPv6 when trying to connect to the port.
* `address`: The source IP address to use.
* `socket`: Specifies the path to a Unix socket (local machine only).
* `tcp`: Optionally specify `Monit` should use TCP when trying to connect to the port.
* `udp`: Optionally specify `Monit` should use UDP when trying to connect to the port.
* `ssl`: Enable the use of SSL for the connection of the test.
* `ssl_options`: This property allows overriding the global SSL configuration for the test.
* `certificate_checksum`: Verify the SSL server certificate by checking its `expected` checksum. You can use either `md5` or `sha1` checksum.
* `certificate_valid`: Send an alert if the certificate will expire in the given number of days.
* `protocol`: Optionally specify the protocol `Monit` should speak when a connection is established. At the moment `Monit` knows how to speak: `apache-status`, `dns`, `dwp`, `fail2ban`, `ftp`, `gps`, `http`, `https`, `imap`, `imaps`, `clamav`, `ldap2`, `ldap3`, `lmtp`, `memcache`, `mongodb`, `mysql`, `nntp`, `ntp3`, `pgsql`, `pop`, `pops`, `postfix-policy`, `radius`, `rdate`, `redis`, `rsync`, `sieve`, `sip`, `smtp`, `smtps`, `spamassassin`, `ssh`, `tns`, `websocket`. This role includes 2 custom protocols: `ssh_command` and `varnish_backend` that would use custom scripts to verify the connection status with the host. The first verifies the execution of a command on the remote host via SSH. The second one verifies the backend status on Varnish, using the local `varnishadm` instance.
* `send_expect`: If `Monit` does not support the protocol spoken by the server, you can write your own protocol-test using `send` and `expect` strings. The `send` statement sends the `value` string to the server port and the `expect` statement compares a string read from the server with the `value` string.
* `timeout`: Timeout in seconds for the test of the connection.
* `retry`: Retry times for the test of the connection.
* `username`: Username that should be used for authentication. It can be used in the following protocols: `apache-status`, `http`, `mysql`, `smtp`, `smtps`, `ssh_command`.
* `password`: Password that should be used for authentication. It can be used in the following protocols: `apache-status`, `http`, `mysql`, `radius`, `smtp`, `smtps`.
* `uri`: URL address that should be used when testing the connection. It can be used in the following protocols: `apache-status`, `http`, `websocket`.
* `method_get`: Use GET HTTP method when testing the connection. It can be used in the following protocols: `http`.
* `method_head`: Use HEAD HTTP method when testing the connection. It can be used in the following protocols: `http`.
* `response_code`: Expected response code for the connection. It can be used in the following protocols: `http`.
* `checksum`: Compare the `md5` or `sha1` checksum of the returned documenta against  the `expected` value. It can be used in the following protocols: `http`.
* `headers`: Dictionary containing the HTTP headers that should be used on the connection. It can be used in the following protocols: `http`.
* `content`: Pattern which is expected in the data returned by the server. It can be used in the following protocols: `http`.
* `properties: List of child statuses to check when executing the connection test. It can be used in the following: `apache-status`. The available properties are: `cleanuplimit`, `closelimit`, `dnslimit`, `gracefullimit`, `keepalivelimit`, `loglimit`, `replylimit`, `requestlimit`, `startlimit`, `waitlimit`.
* `target`: Specifies an alternative recipient for the message. It can be used in the following protocols: `sip`.
* `max_forward`: Limit the number of proxies or gateways that can forward the request to the next server. It can be used in the following protocols: `sip`.
* `origin`: Specifies an alternative origin for the request of the connection test. It can be used in the following protocols: `websocket`.
* `version`: When using `varnish_backend` custom protocol, specifies the `varnishadm` version to be used. When using `websocket` protocol, specifies an alternative version.
* `identity`: Identity file that should be used when testing the connection using `ssh_command` custom protocol.
* `command`: Comman that should be executed on the remote host when testing the connection using `ssh_command` custom protocol.

## Fault tolerance

By default an action is executed if it matches and the corresponding service is set in an error state. However, you can require a test to fail more than once before the error event is triggered and the service state is changed to failed. This is useful to avoid getting alerts on spurious errors, which can happen, especially with network tests.

To enable this functionality on a test, its definition dictionary should include the following key:

    tolerance:
      cycles: 5
      times: 3

If the definition on use `cycles`, the test would fail `cycles` times before execution the action. If it includes `times` also, the test would fail `times` times in `cycles` cycles before the execution.

## Actions

When a test fail or it succeeds again, `Monit` will trigger one of the following actions:

* `alert`: Sends the user an alert event on each state change.
* `restart`: Restarts the service and send an alert. Restart is performed by calling the service's registered restart method or by first calling the stop method followed by the start method if restart is not set.
* `start`: Starts the service by calling the service's registered start method and send an alert.
* `stop`: Stops the service by calling the service's registered stop method and send an alert. If `Monit` stops a service it will not be checked by `Monit` anymore nor restarted again later. To reactivate monitoring of the service again you must explicitly enable monitoring from the web interface or from the console.
* `exec`: Can be used to execute an arbitrary program and send an alert. If you choose this action you must state the program to be executed. You may optionally specify the uid and gid the executed program should switch to upon start. The program is executed only once if the test fails. You can enable execute repetition if the error persists for a given number of cycles.
* `unmonitor`: Will disable monitoring of the service and send an alert. The service will not be checked by `Monit` anymore nor restarted again later. To reactivate monitoring of the service you must explicitly enable monitoring from the web interface or from the console.

Each item of the `tests` list should use one of the following actions.

    action_alert: True

Enable `alert` action.

    action_restart: False

Enable `restart` action.

    action_start: False

Enable `start` action.

    action_stop: False

Enable `stop` action.

    action_exec:
      command: "/usr/local/bin/sms.sh"
      uid: monit
      gid: monit
      repeat: 5

Enable `exec` action. It should contain at least the `command` item.

    action_unmonitor: False

Enable `unmonitor` action.

Each item of the `tests` list may use one of the following actions to enable the trigger of a succeed action.

    succeeded_action_alert: False

Enable `alert` succeeded action.

    succeeded_action_restart: False

Enable `restart` succeeded action.

    succeeded_action_start: False

Enable `start` succeeded action.

    succeeded_action_stop: False

Enable `stop` succeeded action.

    succeeded_action_exec:
      command: "/usr/local/bin/sms.sh"
      uid: monit
      gid: monit
      repeat: 5

Enable `exec` succeeded action. It should contain at least the `command` item.

    succeeded_action_unmonitor: False

Enable `unmonitor` succeeded action.

Dependencies
------------

None.

Example Playbook
----------------

    - hosts: servers
      vars_files:
        - vars/main.yml
      roles:
         - gcoop-libre.monit

*Inside `vars/main.yml`*:

    monit_monitors:
      - name: sshd_rc
        enabled: True
        monitor_file: True
        path: /etc/init.d/ssh
        every_cycles: 5
        group: ssh
        mode_active: True
        tests:
          - test_existence:
              exist: True
            action_alert: True
        alerts:
          - email: email@domain.com
            reminder: 5

License
-------

GPLv2

Author Information
------------------

This role was created in 2017 by [gcoop Cooperativa de Software Libre](https://www.gcoop.coop).
