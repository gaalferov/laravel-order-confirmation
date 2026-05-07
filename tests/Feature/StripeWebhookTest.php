<?php

namespace Tests\Feature;

use App\Services\OrderConfirmationMailer;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Stripe\HttpClient\ClientInterface;
use Tests\TestCase;

class StripeWebhookTest extends TestCase
{
    private string $webhookSecret = 'whsec_test_secret';

    protected function setUp(): void
    {
        parent::setUp();

        config(['stripe.webhook_secret' => $this->webhookSecret]);
        config(['stripe.secret_key' => 'sk_test_fake']);
    }

    private function stripeSignature(string $payload, ?string $secret = null, ?int $timestamp = null): string
    {
        $secret ??= $this->webhookSecret;
        $timestamp ??= time();
        $signedPayload = $timestamp . '.' . $payload;
        $signature = hash_hmac('sha256', $signedPayload, $secret);

        return "t={$timestamp},v1={$signature}";
    }

    private function checkoutSessionPayload(string $eventId = 'evt_test_123', string $sessionId = 'cs_test_456'): string
    {
        return json_encode([
            'id' => $eventId,
            'object' => 'event',
            'type' => 'checkout.session.completed',
            'data' => [
                'object' => [
                    'id' => $sessionId,
                    'object' => 'checkout.session',
                    'amount_total' => 4999,
                    'currency' => 'usd',
                    'customer_details' => [
                        'email' => 'buyer@example.com',
                    ],
                    'shipping_details' => [
                        'name' => 'Jane Doe',
                        'address' => [
                            'line1' => '123 Main St',
                            'line2' => 'Apt 4',
                            'city' => 'Springfield',
                            'state' => 'IL',
                            'postal_code' => '62704',
                            'country' => 'US',
                        ],
                    ],
                ],
            ],
        ]);
    }

    private function nonCheckoutPayload(string $eventId = 'evt_test_789'): string
    {
        return json_encode([
            'id' => $eventId,
            'object' => 'event',
            'type' => 'payment_intent.succeeded',
            'data' => [
                'object' => [
                    'id' => 'pi_test_123',
                    'object' => 'payment_intent',
                ],
            ],
        ]);
    }

    private function mockStripeSessionRetrieve(): void
    {
        $sessionResponse = json_encode([
            'id' => 'cs_test_456',
            'object' => 'checkout.session',
            'amount_total' => 4999,
            'currency' => 'usd',
            'customer_details' => [
                'email' => 'buyer@example.com',
            ],
            'shipping_details' => [
                'name' => 'Jane Doe',
                'address' => [
                    'line1' => '123 Main St',
                    'line2' => 'Apt 4',
                    'city' => 'Springfield',
                    'state' => 'IL',
                    'postal_code' => '62704',
                    'country' => 'US',
                ],
            ],
        ]);

        $lineItemsResponse = json_encode([
            'object' => 'list',
            'data' => [
                [
                    'id' => 'li_1',
                    'object' => 'item',
                    'description' => 'Widget Pro',
                    'quantity' => 2,
                    'amount_total' => 3998,
                    'currency' => 'usd',
                    'price' => [
                        'id' => 'price_123',
                        'product' => [
                            'id' => 'prod_123',
                            'name' => 'Widget Pro',
                        ],
                    ],
                ],
                [
                    'id' => 'li_2',
                    'object' => 'item',
                    'description' => 'Shipping',
                    'quantity' => 1,
                    'amount_total' => 1001,
                    'currency' => 'usd',
                    'price' => [
                        'id' => 'price_456',
                        'product' => [
                            'id' => 'prod_456',
                            'name' => 'Shipping',
                        ],
                    ],
                ],
            ],
        ]);

        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->method('request')->willReturnOnConsecutiveCalls(
            [$sessionResponse, 200, []],
            [$lineItemsResponse, 200, []],
        );

        \Stripe\ApiRequestor::setHttpClient($mockClient);
    }

    // ─── Signature verification ───

    public function test_missing_signature_returns_400(): void
    {
        $payload = $this->checkoutSessionPayload();

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $response->assertStatus(400);
        $response->assertJson(['error' => 'Invalid signature']);
    }

    public function test_invalid_signature_returns_400(): void
    {
        $payload = $this->checkoutSessionPayload();

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => 't=123,v1=invalid_signature_here',
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $response->assertStatus(400);
        $response->assertJson(['error' => 'Invalid signature']);
    }

    public function test_tampered_payload_returns_400(): void
    {
        $originalPayload = $this->checkoutSessionPayload();
        $signature = $this->stripeSignature($originalPayload);

        $tamperedPayload = json_encode(['id' => 'evt_tampered', 'type' => 'malicious']);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $tamperedPayload);

        $response->assertStatus(400);
    }

    public function test_valid_signature_returns_200(): void
    {
        $payload = $this->nonCheckoutPayload();
        $signature = $this->stripeSignature($payload);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $response->assertStatus(200);
        $response->assertJson(['status' => 'ok']);
    }

    // ─── Duplicate handling ───

    public function test_duplicate_event_returns_already_processed(): void
    {
        $eventId = 'evt_duplicate_test';
        Cache::put("stripe_event_{$eventId}", true, now()->addHours(24));

        $payload = $this->nonCheckoutPayload($eventId);
        $signature = $this->stripeSignature($payload);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $response->assertStatus(200);
        $response->assertJson(['status' => 'already processed']);
    }

    public function test_processed_event_is_cached(): void
    {
        $eventId = 'evt_cache_test';
        $payload = $this->nonCheckoutPayload($eventId);
        $signature = $this->stripeSignature($payload);

        $this->assertFalse(Cache::has("stripe_event_{$eventId}"));

        $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $this->assertTrue(Cache::has("stripe_event_{$eventId}"));
    }

    // ─── Non-checkout events ───

    public function test_non_checkout_event_does_not_trigger_email(): void
    {
        $mailer = $this->mock(OrderConfirmationMailer::class);
        $mailer->shouldNotReceive('send');

        $payload = $this->nonCheckoutPayload();
        $signature = $this->stripeSignature($payload);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $response->assertStatus(200);
    }

    // ─── Checkout session completed ───

    public function test_checkout_session_triggers_order_confirmation_email(): void
    {
        $this->mockStripeSessionRetrieve();

        $mailer = $this->mock(OrderConfirmationMailer::class);
        $mailer->shouldReceive('send')
            ->once()
            ->withArgs(function (string $email, array $orderData) {
                return $email === 'buyer@example.com'
                    && $orderData['order_id'] === 'cs_test_456'
                    && $orderData['total'] === 'USD 49.99'
                    && count($orderData['items']) === 2
                    && $orderData['items'][0]['name'] === 'Widget Pro'
                    && $orderData['items'][0]['quantity'] === 2
                    && $orderData['items'][0]['price'] === 'USD 39.98'
                    && $orderData['shipping_address']['name'] === 'Jane Doe'
                    && $orderData['shipping_address']['city'] === 'Springfield';
            });

        $payload = $this->checkoutSessionPayload();
        $signature = $this->stripeSignature($payload);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $response->assertStatus(200);
        $response->assertJson(['status' => 'ok']);
    }

    public function test_mailer_failure_returns_500_for_stripe_retry(): void
    {
        $this->mockStripeSessionRetrieve();

        $mailer = $this->mock(OrderConfirmationMailer::class);
        $mailer->shouldReceive('send')
            ->once()
            ->andThrow(new \RuntimeException('Mail service down'));

        $eventId = 'evt_mail_fail';
        $payload = $this->checkoutSessionPayload($eventId);
        $signature = $this->stripeSignature($payload);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        // Returns 500 so Stripe retries — email should not be lost
        $response->assertStatus(500);
        $response->assertJson(['error' => 'Processing failed']);
        $this->assertFalse(Cache::has("stripe_event_{$eventId}"));
    }

    // ─── Missing template UUID ───

    public function test_missing_template_uuid_skips_email_gracefully(): void
    {
        config(['order.mailtrap_template_uuid' => null]);

        $this->mockStripeSessionRetrieve();

        $mailer = new OrderConfirmationMailer();
        $this->app->instance(OrderConfirmationMailer::class, $mailer);

        Log::shouldReceive('warning')
            ->once()
            ->withArgs(function (string $message) {
                return str_contains($message, 'Mailtrap template UUID not configured');
            });
        Log::shouldReceive('info')->zeroOrMoreTimes();

        $payload = $this->checkoutSessionPayload();
        $signature = $this->stripeSignature($payload);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $response->assertStatus(200);
    }

    // ─── Missing customer email ───

    public function test_missing_customer_email_logs_warning_and_skips(): void
    {
        config(['order.recipient_email' => null]);

        $sessionResponse = json_encode([
            'id' => 'cs_test_no_email',
            'object' => 'checkout.session',
            'amount_total' => 1000,
            'currency' => 'usd',
            'customer_details' => ['email' => null],
            'shipping_details' => null,
        ]);

        $lineItemsResponse = json_encode([
            'object' => 'list',
            'data' => [],
        ]);

        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->method('request')->willReturnOnConsecutiveCalls(
            [$sessionResponse, 200, []],
            [$lineItemsResponse, 200, []],
        );
        \Stripe\ApiRequestor::setHttpClient($mockClient);

        $mailer = $this->mock(OrderConfirmationMailer::class);
        $mailer->shouldNotReceive('send');

        $payload = $this->checkoutSessionPayload('evt_no_email', 'cs_test_no_email');
        $signature = $this->stripeSignature($payload);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $response->assertStatus(200);
    }

    // ─── Stripe API failure ───

    public function test_stripe_api_failure_returns_500_for_retry(): void
    {
        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->method('request')->willThrowException(
            new \Stripe\Exception\ApiConnectionException('Connection to Stripe failed')
        );
        \Stripe\ApiRequestor::setHttpClient($mockClient);

        $mailer = $this->mock(OrderConfirmationMailer::class);
        $mailer->shouldNotReceive('send');

        $eventId = 'evt_stripe_fail';
        $payload = $this->checkoutSessionPayload($eventId, 'cs_test_fail');
        $signature = $this->stripeSignature($payload);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        // Returns 500 so Stripe retries — event NOT cached
        $response->assertStatus(500);
        $response->assertJson(['error' => 'Processing failed']);
        $this->assertFalse(Cache::has("stripe_event_{$eventId}"));
    }

    // ─── Empty line items ───

    public function test_checkout_with_empty_line_items_still_sends_email(): void
    {
        $sessionResponse = json_encode([
            'id' => 'cs_test_empty_items',
            'object' => 'checkout.session',
            'amount_total' => 0,
            'currency' => 'usd',
            'customer_details' => ['email' => 'buyer@example.com'],
            'shipping_details' => null,
        ]);

        $lineItemsResponse = json_encode([
            'object' => 'list',
            'data' => [],
        ]);

        $mockClient = $this->createMock(ClientInterface::class);
        $mockClient->method('request')->willReturnOnConsecutiveCalls(
            [$sessionResponse, 200, []],
            [$lineItemsResponse, 200, []],
        );
        \Stripe\ApiRequestor::setHttpClient($mockClient);

        $mailer = $this->mock(OrderConfirmationMailer::class);
        $mailer->shouldReceive('send')
            ->once()
            ->withArgs(function (string $email, array $orderData) {
                return $email === 'buyer@example.com'
                    && $orderData['order_id'] === 'cs_test_empty_items'
                    && $orderData['items'] === []
                    && $orderData['total'] === 'USD 0.00'
                    && $orderData['shipping_address'] === null;
            });

        $payload = $this->checkoutSessionPayload('evt_empty_items', 'cs_test_empty_items');
        $signature = $this->stripeSignature($payload);

        $response = $this->call('POST', '/api/stripe/webhook', [], [], [], [
            'HTTP_STRIPE_SIGNATURE' => $signature,
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        $response->assertStatus(200);
        $response->assertJson(['status' => 'ok']);
    }
}
