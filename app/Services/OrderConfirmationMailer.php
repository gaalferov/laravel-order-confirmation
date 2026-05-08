<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;
use Mailtrap\MailtrapClient;
use Mailtrap\Mime\MailtrapEmail;
use Symfony\Component\Mime\Address;

class OrderConfirmationMailer
{
    public function send(string $recipientEmail, array $orderData): void
    {
        $templateUuid = config('order.mailtrap_template_uuid');

        if (! $templateUuid) {
            Log::warning('Mailtrap template UUID not configured, skipping order confirmation email', [
                'order_id' => $orderData['order_id'],
            ]);

            return;
        }

        try {
            $email = (new MailtrapEmail)
                ->from(new Address(
                    config('mail.from.address'),
                    config('mail.from.name'),
                ))
                ->to(new Address($recipientEmail))
                ->templateUuid($templateUuid)
                ->templateVariables([
                    'order_id' => $orderData['order_id'],
                    'items' => $orderData['items'],
                    'total' => $orderData['total'],
                    'shipping_address' => $orderData['shipping_address'],
                ]);

            MailtrapClient::initSendingEmails(
                apiKey: config('services.mailtrap.api_key'),
                isSandbox: (bool) config('services.mailtrap.sandbox'),
                inboxId: config('services.mailtrap.inbox_id'),
            )->send($email);

            Log::info('Order confirmation email sent', [
                'order_id' => $orderData['order_id'],
                'recipient' => $recipientEmail,
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to send order confirmation email', [
                'order_id' => $orderData['order_id'],
                'recipient' => $recipientEmail,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }
}
