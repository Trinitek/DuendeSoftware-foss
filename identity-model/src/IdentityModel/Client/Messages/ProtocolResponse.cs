// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Text.Json;
using Duende.IdentityModel.Internal;

namespace Duende.IdentityModel.Client;

/// <summary>
/// A protocol response
/// </summary>
public class ProtocolResponse
{
    /// <summary>
    /// Initializes a protocol response from an HTTP response
    /// </summary>
    /// <typeparam name="T">Specific protocol response type</typeparam>
    /// <param name="httpResponse">The HTTP response.</param>
    /// <param name="initializationData">The initialization data.</param>
    /// <param name="skipJsonParsing">Disables parsing of json</param>
    /// <param name="onResponseCreated">An action that is invoked after the response is created, allowing for additional processing of the response.</param>
    /// <returns></returns>
    public static async Task<T> FromHttpResponseAsync<T>(
        HttpResponseMessage httpResponse,
        object? initializationData = null,
        bool skipJsonParsing = false,
        Action<T>? onResponseCreated = null)
        where T : ProtocolResponse, new()
    {
        var response = new T
        {
            HttpResponse = httpResponse
        };

        onResponseCreated?.Invoke(response);

        // try to read content
        var content = string.Empty;
        try
        {
            // In .NET, empty content is represented in an HttpResponse with the EmptyContent type,
            // the Content property is not nullable, and ReadAsStringAsync returns the empty string.
            //
            // BUT, in .NET Framework, empty content is represented with a null, and attempting to
            // call ReadAsStringAsync would throw a NRE.
            if (httpResponse.Content != null)
            {
                content = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait();
            }
            response.Raw = content;
        }
        catch (Exception ex)
        {
            response.ErrorType = ResponseErrorType.Exception;
            response.Exception = ex;
        }

        // some HTTP error - try to parse body as JSON but allow non-JSON as well
        if (httpResponse.IsSuccessStatusCode != true &&
            httpResponse.StatusCode != HttpStatusCode.BadRequest)
        {
            response.ErrorType = ResponseErrorType.Http;

            if (!skipJsonParsing && content.IsPresent())
            {
                try
                {
                    response.Json = JsonDocument.Parse(content!).RootElement;
                }
                catch { }
            }

            await response.InitializeAsync(initializationData).ConfigureAwait();
            return response;
        }

        if (httpResponse.StatusCode == HttpStatusCode.BadRequest)
        {
            response.ErrorType = ResponseErrorType.Protocol;
        }

        // either 200 or 400 - both cases need a JSON response (if present), otherwise error
        try
        {
            if (!skipJsonParsing && content.IsPresent())
            {
                response.Json = JsonDocument.Parse(content!).RootElement;
            }
        }
        catch (Exception ex)
        {
            response.ErrorType = ResponseErrorType.Exception;
            response.Exception = ex;
        }

        if (httpResponse.Headers.TryGetValues(OidcConstants.HttpHeaders.DPoPNonce, out var nonceHeaders))
        {
            if (nonceHeaders.Count() == 1)
            {
                response.DPoPNonce = nonceHeaders.First();
            }
        }


        await response.InitializeAsync(initializationData).ConfigureAwait();
        return response;
    }

    /// <summary>
    /// Initializes a protocol response from an exception
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="ex">The ex.</param>
    /// <param name="errorMessage">The error message.</param>
    /// <returns></returns>
    public static T FromException<T>(Exception ex, string? errorMessage = null) where T : ProtocolResponse, new()
    {
        var response = new T
        {
            Exception = ex,
            ErrorType = ResponseErrorType.Exception,
            ErrorMessage = errorMessage
        };

        return response;
    }

    /// <summary>
    /// Allows to initialize instance specific data.
    /// </summary>
    /// <param name="initializationData">The initialization data.</param>
    /// <returns></returns>
    protected virtual Task InitializeAsync(object? initializationData = null) => Task.CompletedTask;

    /// <summary>
    /// Gets the HTTP response.
    /// </summary>
    /// <value>
    /// The HTTP response.
    /// </value>
    public HttpResponseMessage? HttpResponse { get; protected set; }

    /// <summary>
    /// Gets the raw protocol response (if present).
    /// </summary>
    /// <value>
    /// The raw.
    /// </value>
    public string? Raw { get; protected set; }

    /// <summary>
    /// Gets the protocol response as JSON (if present).
    /// </summary>
    /// <value>
    /// The json.
    /// </value>
    public JsonElement? Json { get; protected set; }

    /// <summary>
    /// Gets the exception (if present).
    /// </summary>
    /// <value>
    /// The exception.
    /// </value>
    public Exception? Exception { get; protected set; }

    /// <summary>
    /// Gets a value indicating whether an error occurred.
    /// </summary>
    /// <value>
    ///   <c>true</c> if an error occurred; otherwise, <c>false</c>.
    /// </value>
    public bool IsError => Error.IsPresent() || ErrorType != ResponseErrorType.None;

    /// <summary>
    /// Gets the type of the error.
    /// </summary>
    /// <value>
    /// The type of the error.
    /// </value>
    public ResponseErrorType ErrorType { get; protected set; } = ResponseErrorType.None;

    /// <summary>
    /// Gets or sets an explicit error message.
    /// </summary>
    /// <value>
    /// The type of the error.
    /// </value>
    protected string? ErrorMessage { get; set; }

    /// <summary>
    /// Gets the HTTP status code - or <c>0</c> when <see cref="HttpResponse" /> is <see langword="null"/>.
    /// </summary>
    /// <value>
    /// The HTTP status code.
    /// </value>
    public HttpStatusCode HttpStatusCode => HttpResponse?.StatusCode ?? default(HttpStatusCode);

    /// <summary>
    /// Gets the HTTP error reason - or <see langword="null"/> when <see cref="HttpResponse" /> is <see langword="null"/>.
    /// </summary>
    /// <value>
    /// The HTTP error reason.
    /// </value>
    public string? HttpErrorReason => HttpResponse?.ReasonPhrase ?? default;

    /// <summary>
    /// Gets the error.
    /// </summary>
    /// <value>
    /// The error.
    /// </value>
    public string? Error
    {
        get
        {
            if (ErrorMessage.IsPresent())
            {
                return ErrorMessage;
            }
            if (ErrorType == ResponseErrorType.Http)
            {
                return HttpErrorReason;
            }
            if (ErrorType == ResponseErrorType.Exception)
            {
                return Exception!.Message;
            }

            return TryGet(OidcConstants.TokenResponse.Error);
        }
    }

    /// <summary>
    /// Tries to get a specific value from the JSON response.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <returns></returns>
    public string? TryGet(string name) => Json?.TryGetString(name);

    /// <summary>
    /// The returned DPoP nonce header.
    /// </summary>
    public string? DPoPNonce { get; set; }
}
