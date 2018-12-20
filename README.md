# slack-verify

[Read the official documentation from Slack](https://api.slack.com/docs/verifying-requests-from-slack)


> Slack signs its requests using a secret that's unique to your app.
> Slack creates a unique string for your app and shares it with you. Verify requests from Slack with confidence by verifying signatures using your signing secret.
> On each HTTP request that Slack sends, we add an X-Slack-Signature HTTP header. The signature is created by combining the signing secret with the body of the request we're sending using a standard HMAC-SHA256 keyed hash.
> The resulting signature is unique to each request and doesn't directly contain any secret information. That keeps your app secure, preventing bad actors from causing mischief.
