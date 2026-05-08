<?php

return [
    'mailtrap' => [
        'api_key' => env('MAILTRAP_API_KEY'),
        'host' => env('MAILTRAP_HOST', 'send.api.mailtrap.io'),
        'sandbox' => filter_var(env('MAILTRAP_SANDBOX', false), FILTER_VALIDATE_BOOLEAN),
        'inbox_id' => env('MAILTRAP_INBOX_ID'),
    ],
];
