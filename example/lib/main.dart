import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_dart/identity/p256.dart';
import 'package:convert/convert.dart';
import 'package:flutter/material.dart';
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
  final _p256Plugin = SecureP256();

  String _publicKey = 'Unknown';
  String _signed = 'Unknown';
  bool? _verified;

  final _payloadController = TextEditingController(
    text: 'Hello world',
  );

  String get alias => 'test_alias';

  String get _verifyPayload => _payloadController.text;

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
              ),
            ),
            ElevatedButton(
              onPressed: () {
                _p256Plugin.getPublicKey(alias).then(
                      (r) => setState(() => _publicKey = hex.encode(r.rawKey)),
                    );
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
                    .then((r) => setState(() => _signed = hex.encode(r)));
              },
              child: const Text('Sign'),
            ),
            ElevatedButton(
              onPressed: () {
                _p256Plugin
                    .verify(
                      Uint8List.fromList(utf8.encode(_verifyPayload)),
                      P256PublicKey.fromRaw(
                        Uint8List.fromList(hex.decode(_publicKey)),
                      ),
                      Uint8List.fromList(hex.decode(_signed)),
                    )
                    .then((r) => setState(() => _verified = r));
              },
              child: const Text('verify'),
            ),
          ],
        ),
      ),
    );
  }
}
