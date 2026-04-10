<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
  http_response_code(405);
  echo json_encode(['ok' => false, 'error' => 'method_not_allowed']);
  exit;
}

$get = static function (string $key, int $maxLen = 5000): string {
  $v = $_POST[$key] ?? '';
  if (!is_string($v)) return '';
  $v = trim($v);
  if (strlen($v) > $maxLen) $v = substr($v, 0, $maxLen);
  return $v;
};

$honeypot = $get('website', 200);
if ($honeypot !== '') {
  http_response_code(204);
  exit;
}

$nome = $get('nome', 120);
$tipo = $get('tipo_attivita', 120);
$telefono = $get('telefono', 40);
$email = $get('email', 180);
$desideri = $get('desideri', 2000);

if ($nome === '' || $tipo === '' || $telefono === '' || $email === '') {
  http_response_code(400);
  echo json_encode(['ok' => false, 'error' => 'missing_fields']);
  exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  http_response_code(400);
  echo json_encode(['ok' => false, 'error' => 'invalid_email']);
  exit;
}

$digits = preg_replace('/[^\d]/', '', $telefono);
if ($digits === null || strlen($digits) < 8 || strlen($digits) > 15) {
  http_response_code(400);
  echo json_encode(['ok' => false, 'error' => 'invalid_phone']);
  exit;
}

$apiKey = getenv('BREVO_API_KEY');
if (!is_string($apiKey) || trim($apiKey) === '') {
  $keyFiles = [
    __DIR__ . '/../private/brevo.key',
    __DIR__ . '/private/brevo.key',
    __DIR__ . '/brevo.key'
  ];
  foreach ($keyFiles as $keyFile) {
    if (is_file($keyFile)) {
      $apiKey = trim((string)file_get_contents($keyFile));
      if ($apiKey !== '') break;
    }
  }
}

$apiKey = is_string($apiKey) ? trim($apiKey) : '';
if ($apiKey === '') {
  http_response_code(500);
  echo json_encode(['ok' => false, 'error' => 'missing_brevo_key']);
  exit;
}

$subject = 'Richiesta informazioni — PVRFACILE';

$text = implode("\n", array_filter([
  'Nuova richiesta dal sito PVRfacile.it',
  '',
  'Nome: ' . $nome,
  'Tipo attività: ' . $tipo,
  'Telefono: ' . $telefono,
  'Email: ' . $email,
  $desideri !== '' ? 'Cosa desideri: ' . $desideri : '',
  '',
  'IP: ' . ($_SERVER['REMOTE_ADDR'] ?? ''),
  'User-Agent: ' . ($_SERVER['HTTP_USER_AGENT'] ?? ''),
]));

$html = nl2br(htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));

$payload = [
  'sender' => [
    'name' => 'PVRfacile.it',
    'email' => 'info@pvrfacile.it'
  ],
  'to' => [
    ['email' => 'info@pvrfacile.it']
  ],
  'replyTo' => [
    'email' => $email,
    'name' => $nome
  ],
  'subject' => $subject,
  'htmlContent' => '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5">' . $html . '</div>'
];

[$resp, $status] = (static function (string $apiKey, array $payload): array {
  $body = json_encode($payload);
  if (!is_string($body)) return [false, 0];

  if (function_exists('curl_init')) {
    $ch = curl_init('https://api.brevo.com/v3/smtp/email');
    if ($ch === false) return [false, 0];
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
      'accept: application/json',
      'content-type: application/json',
      'api-key: ' . $apiKey
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    $resp = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$resp, $status];
  }

  $context = stream_context_create([
    'http' => [
      'method' => 'POST',
      'header' => implode("\r\n", [
        'accept: application/json',
        'content-type: application/json',
        'api-key: ' . $apiKey
      ]),
      'content' => $body,
      'ignore_errors' => true
    ]
  ]);

  $resp = @file_get_contents('https://api.brevo.com/v3/smtp/email', false, $context);
  $status = 0;
  if (isset($http_response_header) && is_array($http_response_header)) {
    foreach ($http_response_header as $h) {
      if (preg_match('/^HTTP\/\d+\.\d+\s+(\d+)/', $h, $m) === 1) {
        $status = (int)$m[1];
        break;
      }
    }
  }
  return [$resp, $status];
})($apiKey, $payload);

if ($resp === false || $status < 200 || $status >= 300) {
  http_response_code(502);
  echo json_encode(['ok' => false, 'error' => 'brevo_send_failed', 'status' => $status]);
  exit;
}

echo json_encode(['ok' => true]);
