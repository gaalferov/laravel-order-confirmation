<?php

use App\Http\Controllers\StripeWebhookController;
use Illuminate\Support\Facades\Route;

Route::post('/stripe/webhook', StripeWebhookController::class)
    ->middleware('throttle:120,1')
    ->name('stripe.webhook');
