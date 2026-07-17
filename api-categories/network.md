# Network API

This category covers Windows API functions commonly related to network initialization, HTTP communication, URL handling, and socket activity.

Network APIs should be interpreted as behavioral indicators during PE malware analysis. A single network-related API should not be treated as proof of malicious behavior.

## InternetOpenA / InternetOpenW

### General Purpose

Initializes an application's use of WinINet functions.

### Analysis Meaning

When `InternetOpenA` or `InternetOpenW` appears in a PE import table, it may indicate that the program can use WinINet-based network functionality.

This API becomes more meaningful when it appears together with URL opening, HTTP request, or data reading APIs.

### What to Review

- Check whether URLs, domains, or IP addresses appear in strings.
- Review whether related WinINet APIs are also imported.
- Compare the import with decompiler output to confirm whether it is called.
- Avoid making a conclusion from this API alone.

## InternetOpenUrlA / InternetOpenUrlW

### General Purpose

Opens a resource specified by a URL.

### Analysis Meaning

`InternetOpenUrlA` or `InternetOpenUrlW` may indicate URL-based network access.

This API should be reviewed together with visible URL strings and nearby data reading logic.

### What to Review

- Check whether the URL is hardcoded or built at runtime.
- Review whether the URL uses HTTP or HTTPS.
- Check whether the program reads data after opening the URL.
- Compare the URL access with strings and code flow.

## InternetReadFile

### General Purpose

Reads data from an opened internet handle.

### Analysis Meaning

`InternetReadFile` may indicate that the program receives data from a network resource.

This API becomes more meaningful when it appears after URL opening or HTTP request APIs.

### What to Review

- Identify which internet handle is being read.
- Check where the received data is stored.
- Review whether the data is written to a file or processed in memory.
- Compare the API usage with file system and memory APIs.

## HttpOpenRequestA / HttpOpenRequestW

### General Purpose

Creates an HTTP request handle.

### Analysis Meaning

`HttpOpenRequestA` or `HttpOpenRequestW` may indicate that the program prepares an HTTP request.

This API should be reviewed with related connection and send request APIs.

### What to Review

- Check the HTTP method if visible.
- Review whether hostnames or paths appear in strings.
- Check whether custom headers are used.
- Compare the request setup with following network calls.

## HttpSendRequestA / HttpSendRequestW

### General Purpose

Sends an HTTP request to a server.

### Analysis Meaning

`HttpSendRequestA` or `HttpSendRequestW` may indicate outbound HTTP communication.

This does not prove malicious behavior by itself. It should be reviewed together with destination strings, request data, and response handling.

### What to Review

- Check the destination host or URL.
- Review whether request data is sent.
- Check whether the response is read with `InternetReadFile`.
- Compare network behavior with file, Registry, or process activity.

## WSAStartup

### General Purpose

Initializes the Winsock library for socket-based network operations.

### Analysis Meaning

`WSAStartup` may indicate that the program can use socket APIs.

This API is common in software that performs network communication and should be reviewed with related socket functions.

### What to Review

- Check whether socket-related APIs are also imported.
- Review whether IP addresses, hostnames, or ports appear in strings.
- Compare the import with code references.
- Treat this API as network context, not as a final indicator.