<?php

namespace App\Http\Controllers;

use App\Services\OrderConfirmationMailer;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Stripe\Checkout\Session;
use Stripe\Event;
use Stripe\Exception\SignatureVerificationException;
use Stripe\Webhook;

class StripeWebhookController extends Controller
{
    private const ZERO_DECIMAL_CURRENCIES = [
        'bif', 'clp', 'djf', 'gnf', 'jpy', 'kmf', 'krw',
        'mga', 'pyg', 'rwf', 'ugx', 'vnd', 'vuv', 'xaf', 'xof', 'xpf',
    ];

    public function __construct(
        private readonly OrderConfirmationMailer $mailer,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        try {
            $event = Webhook::constructEvent(
                $request->getContent(),
                $request->header('Stripe-Signature', ''),
                config('stripe.webhook_secret'),
            );
        } catch (SignatureVerificationException $e) {
            Log::warning('Stripe webhook signature verification failed', [
                'error' => $e->getMessage(),
            ]);

            return response()->json(['error' => 'Invalid signature'], 400);
        } catch (\UnexpectedValueException $e) {
            Log::warning('Stripe webhook payload invalid', [
                'error' => $e->getMessage(),
            ]);

            return response()->json(['error' => 'Invalid payload'], 400);
        }

        $cacheKey = 'stripe_event_' . $event->id;

        if (Cache::has($cacheKey)) {
            Log::info('Stripe webhook duplicate event skipped', ['event_id' => $event->id]);

            return response()->json(['status' => 'already processed']);
        }

        if ($event->type === 'checkout.session.completed') {
            try {
                $this->handleCheckoutSessionCompleted($event);
            } catch (\Exception $e) {
                Log::error('Failed to process checkout session', [
                    'event_id' => $event->id,
                    'error' => $e->getMessage(),
                ]);

                return response()->json(['error' => 'Processing failed'], 500);
            }
        }

        Cache::put($cacheKey, true, now()->addHours(24));

        return response()->json(['status' => 'ok']);
    }

    private function handleCheckoutSessionCompleted(Event $event): void
    {
        $session = Session::retrieve($event->data->object->id);
        $lineItems = Session::allLineItems($event->data->object->id, ['expand' => ['data.price.product']]);

        $customerEmail = $session->customer_details?->email
            ?? config('order.recipient_email');

        if (! $customerEmail) {
            Log::warning('Checkout session has no customer email', [
                'session_id' => $session->id,
            ]);

            return;
        }

        $items = [];
        foreach ($lineItems->data ?? [] as $lineItem) {
            $items[] = [
                'name' => $lineItem->description,
                'quantity' => $lineItem->quantity,
                'price' => $this->formatAmount($lineItem->amount_total, $lineItem->currency),
            ];
        }

        $shipping = $session->shipping_details;

        $orderData = [
            'order_id' => $session->id,
            'items' => $items,
            'total' => $this->formatAmount($session->amount_total, $session->currency),
            'shipping_address' => $shipping ? [
                'name' => $shipping->name ?? '',
                'line1' => $shipping->address->line1 ?? '',
                'line2' => $shipping->address->line2 ?? '',
                'city' => $shipping->address->city ?? '',
                'state' => $shipping->address->state ?? '',
                'postal_code' => $shipping->address->postal_code ?? '',
                'country' => $shipping->address->country ?? '',
            ] : null,
        ];

        Log::info('Sending order confirmation email', [
            'session_id' => $session->id,
            'customer_email' => $customerEmail,
            'items_count' => count($items),
        ]);

        $this->mailer->send($customerEmail, $orderData);
    }

    private function formatAmount(int $amount, string $currency): string
    {
        $upper = strtoupper($currency);

        if (in_array(strtolower($currency), self::ZERO_DECIMAL_CURRENCIES, true)) {
            return $upper . ' ' . number_format($amount, 0);
        }

        return $upper . ' ' . number_format($amount / 100, 2);
    }
}
