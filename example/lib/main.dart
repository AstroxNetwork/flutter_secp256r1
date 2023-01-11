import 'dart:convert';

import 'package:agent_dart/utils/number.dart';
import 'package:agent_dart/utils/extension.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:p256/p256.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final _p256Plugin = P256();

  String _publicKey = 'Unknown';
  String _signed = 'Unknown';
  bool? _verified;

  String get alias => 'test_alias';

  String _verifyPayload = 'Hello world';
  // String get verifyPublicKey =>
  //     '3059301306072a8648ce3d020106082a8648ce3d03010703420004ea9970fb9b05e8ac249bfb4ca53896f6ace37174ae89a3ed24d5593f9150d1f3821ec2a36109678c7f2362b0d7c16349408baaa342c67061a1c3b06ed1609426';
  // String get verifySignature =>
  //     '3045022100ab4f14025772c2b95343851ef95c3cffc764dc08d67074857577b6dd39c9be5b02207ec21f8985eb52a0bbc7094fde49991a4daece57d69e4082c2336cb1c7db1f7b';

  final TextEditingController _payloadController = TextEditingController()
    ..text = 'Hello world';

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: ListView(
          children: [
            SelectableText('getPublicKey: $_publicKey\n'),
            SelectableText('sign: $_signed\n'),
            SelectableText('verify: $_verified\n'),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 16),
              child: TextField(
                controller: _payloadController,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  hintText: 'Enter a search term',
                ),
                onChanged: (e) {
                  setState(() {
                    _verifyPayload = e;
                  });
                },
              ),
            ),
            ElevatedButton(
              onPressed: () {
                _p256Plugin.getPublicKey(alias).then((r) => setState(() {
                      _publicKey = bytesToHex(r);
                    }));
              },
              child: const Text('getPublicKey'),
            ),
            ElevatedButton(
              onPressed: () {
                _p256Plugin
                    .sign(
                      alias,
                      Uint8List.fromList(utf8.encode(_verifyPayload)),
                    )
                    .then((r) => setState(() {
                          _signed = bytesToHex(r);
                        }));
              },
              child: const Text('Sign'),
            ),
            ElevatedButton(
              onPressed: () {
                _p256Plugin
                    .verify(
                      _verifyPayload.plainToU8a(),
                      _publicKey.toU8a(),
                      _signed.toU8a(),
                    )
                    .then((r) => setState(() {
                          _verified = r;
                        }));
              },
              child: const Text('verify'),
            ),
          ],
        ),
      ),
    );
  }
}
