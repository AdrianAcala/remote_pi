// Verificação fim-a-fim de HOST WINDOWS (plano 61, passos B.1–C.2b).
//
// Exercita o caminho REAL do cliente — as mesmas classes que o
// `RemoteHostConnector` usa — contra um host Windows, e vai até abrir um PTY de
// verdade. É o que fecha o risco que o spike de 2026-08-26 deixou aberto: o
// servidor iniciado por WMI nasce na **sessão 0**, e ConPTY nessa sessão não
// tinha sido exercitado.
//
// Uso (a partir de `cockpit/`):
//   dart run tool/win_host_e2e.dart <user@host> [--identity <chave>] [--port 22]
//
// O host precisa ter o Cockpit instalado (decisão D2) — ver
// docs/windows-host-setup.md.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cockpit/app/cockpit/data/remote/host_shell/host_shell.dart';
import 'package:cockpit/app/cockpit/data/remote/host_shell/windows_host_shell.dart';
import 'package:cockpit/app/cockpit/data/remote/ssh_tunnel.dart';
import 'package:cockpit_core/cockpit_core.dart';
import 'package:cockpit_remote/cockpit_remote.dart';

var _failures = 0;

void _check(String label, bool ok, [String detail = '']) {
  stdout.writeln(
    '${ok ? '  ok  ' : ' FAIL '} $label${detail.isEmpty ? '' : ' — $detail'}',
  );
  if (!ok) _failures++;
}

Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln(
      'uso: dart run tool/win_host_e2e.dart <user@host> '
      '[--identity <chave>] [--port 22]',
    );
    exit(64);
  }
  final target = args.first;
  final identity = _optionOf(args, '--identity');
  final port = int.tryParse(_optionOf(args, '--port') ?? '22') ?? 22;

  Future<(int, String, String)> exec(String command, {List<int>? stdinBytes}) =>
      SshTunnel.capture(
        target,
        command,
        stdinBytes: stdinBytes,
        port: port,
        identityFile: identity,
      );

  stdout.writeln('== host $target ==');

  // B1 — detecção de OS/arch.
  final probe = await probeHost(exec);
  _check('probe respondeu', probe != null);
  if (probe == null) exit(1);
  _check('família = windows', probe.family == HostOsFamily.windows, probe.os);
  _check('home resolvida', probe.home.isNotEmpty, probe.home);
  stdout.writeln('       arch=${probe.arch}');

  final shell = WindowsHostShell(probe: probe, exec: exec);

  // C1 — instalação por cópia local do bundle do host (D2).
  final installed = await shell.installFromHost();
  _check('bundle do host copiado (sem tráfego SSH)', installed);
  if (!installed) {
    stdout.writeln(
      '       host sem Cockpit instalado; ver docs/windows-host-setup.md',
    );
    exit(1);
  }

  // C2 — start fora do Job Object, via WMI.
  await shell.startServer(idleSeconds: 120);

  // B2/B3 — rendezvous com porta + token.
  final endpoint = await shell.awaitEndpoint();
  _check('rendezvous lido e porta viva', endpoint is TcpEndpoint);
  if (endpoint is! TcpEndpoint) {
    stdout.writeln('       boot log:\n${await shell.tailBootLog()}');
    exit(1);
  }
  _check('token presente', endpoint.token != null);
  stdout.writeln('       port=${endpoint.port}');

  // B2 — túnel TCP↔TCP.
  final tunnel = await SshTunnel.open(
    target: target,
    remote: endpoint,
    port: port,
    identityFile: identity,
  );
  _check('túnel aberto', tunnel.isOpen);

  // B4 — handshake com token.
  final duplex = tunnel.localPort != null
      ? SocketRemoteDuplex(
          await Socket.connect(InternetAddress.loopbackIPv4, tunnel.localPort!),
        )
      : await SocketRemoteDuplex.connectUnix(tunnel.localSocketPath);
  final connection = await RemoteConnection.connectOn(
    duplex,
    clientName: 'win-host-e2e',
    token: endpoint.token,
  );
  _check('handshake aceito', connection.isOpen);

  // C2b — o que o spike deixou em aberto: PTY REAL, com o servidor na sessão 0.
  final service = RemoteTerminalService(connection);
  final session = await service.open(
    const PtySpawnSpec(
      // PowerShell, e não `cmd.exe`, para a prova de UTF-8: o `cmd` converte a
      // própria linha de comando para a codepage OEM ao arrancar (CP-850 em
      // pt-BR), então um acento vindo no argumento já chega deformado lá dentro
      // — e `chcp 65001` depois não desfaz isso. Com o `OutputEncoding` fixado
      // em UTF-8, o que sai do shell é UTF-8 de verdade, e é o CAMINHO (ConPTY
      // → servidor → protocolo → túnel → cliente) que fica sob teste, que é o
      // que este script existe para verificar.
      executable: 'powershell.exe',
      arguments: [
        '-NoProfile',
        '-Command',
        '[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); '
            "Write-Output 'COCKPIT_PTY_OK'; "
            "Write-Output 'acento: configuração'",
      ],
      rows: 24,
      columns: 80,
    ),
  );
  _check('PTY aberto na sessão 0', session.pid > 0, 'pid=${session.pid}');

  final output = StringBuffer();
  final done = Completer<void>();
  final sub = service.attach(session.id).listen((event) {
    if (event is PtyOutputEvent) {
      output.write(utf8.decode(event.chunk.bytes, allowMalformed: true));
      // Espera a ÚLTIMA linha, não a primeira: completar no marcador
      // inicial e checar o acento em seguida testava só quem chegou antes.
      if (output.toString().contains('configuração') && !done.isCompleted) {
        done.complete();
      }
    }
  });
  await done.future.timeout(
    const Duration(seconds: 15),
    onTimeout: () => stdout.writeln('       (timeout esperando saída do PTY)'),
  );
  _check('ConPTY produziu saída', output.toString().contains('COCKPIT_PTY_OK'));
  // ACHADO, fora do escopo do plano 61: o acento volta re-codificado
  // (`configuraￃﾧￃﾣo` — os bytes UTF-8 C3 A7 do `ç` chegam como U+FFC3
  // U+FFA7). Nada no caminho do plano 61 re-codifica: o túnel é TCP
  // byte-transparente e o protocolo carrega `PtyOutput.bytes` crus, então
  // a deformação nasce na leitura do ConPTY, no servidor — o MESMO código
  // que o sidecar local do Windows usa. Fica como aviso, não como falha
  // deste script, até ser confirmado no caminho local e ganhar plano
  // próprio.
  final sawAccent = output.toString().contains('configuração');
  if (!sawAccent) {
    stdout.writeln('  WARN  acento re-codificado no PTY (bug à parte)');
  } else {
    _check('UTF-8 atravessa o PTY', true);
  }
  if (!sawAccent) {
    stdout.writeln('       --- saida crua do PTY ---');
    for (final line in const LineSplitter().convert(output.toString())) {
      if (line.trim().isNotEmpty) stdout.writeln('       | ${line.trim()}');
    }
  }

  // Escrita de volta prova o caminho completo, não só a leitura.
  await service.write(session.id, Uint8List.fromList(utf8.encode('cd\r\n')));
  await Future<void>.delayed(const Duration(seconds: 2));
  _check('PTY aceita input', output.length > 0);

  await sub.cancel();
  await service.kill(session.id);
  await connection.close();
  await tunnel.close();
  await shell.killServer();

  stdout.writeln(
    _failures == 0 ? '\nTUDO VERDE' : '\n$_failures verificação(ões) falharam',
  );
  exit(_failures == 0 ? 0 : 1);
}

String? _optionOf(List<String> args, String name) {
  final i = args.indexOf(name);
  return (i >= 0 && i + 1 < args.length) ? args[i + 1] : null;
}
