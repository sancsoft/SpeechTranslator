using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Microsoft.MT.Api.TestUtils
{
    internal class QueueItem
    {
        public QueueItem(WebSocketMessageType opCode, ArraySegment<byte> content)
        {
            if (opCode == WebSocketMessageType.Close) throw new ArgumentOutOfRangeException("opCode");
            if (content == null) throw new ArgumentNullException("content");

            this.OpCode = opCode;
            this.Content = content;
            this.CompletionSource = new TaskCompletionSource<bool>();
        }

        /// Message type.
        public WebSocketMessageType OpCode { get; private set; }
        /// Message content.
        public ArraySegment<byte> Content { get; private set; }
        /// Completion source to signal to sender when message has been sent.
        public TaskCompletionSource<bool> CompletionSource { get; private set; }
    }

    public class SpeechClient : IDisposable
    {
        /// <summary>
        /// Supported features of the API
        /// </summary>
        [Flags]
        public enum Features
        {
            /// <summary>
            /// Gets the text to speech (TTS) audio of the translation
            /// </summary>
            TextToSpeech = 1,

            /// <summary>
            /// Gets partial speech recognitions (hypotheses)
            /// </summary>
            Partial = 2,

            /// <summary>
            /// Fast Partial results (every 500ms)
            /// </summary>
            FastPartial = 4
        }

        /// <summary>
        /// Defines how profanities need to be handled by the service
        /// </summary>
        public enum ProfanityFilter
        {
            /// <summary>
            /// Only moderate profanities will be returned in text and audio
            /// </summary>
            Moderate,

            /// <summary>
            /// No profanity filter is done server side
            /// </summary>
            Off,

            /// <summary>
            /// All profanities will be removed from text and audio by the service
            /// </summary>
            Strict
        }

        private const int ReceiveChunkSize = 8*1024;
        private const int SendChunkSize = 8*1024;

        private SpeechClientOptions options;
        private CancellationToken cancellationToken;
        private ClientWebSocket webSocketclient;
        private Uri clientWsUri;

        public event EventHandler<ArraySegment<byte>> OnTextData;
        public event EventHandler<ArraySegment<byte>> OnEndOfTextData;
        public event EventHandler<ArraySegment<byte>> OnBinaryData;
        public event EventHandler<ArraySegment<byte>> OnEndOfBinaryData;
        public event EventHandler Disconnected;
        public event EventHandler<Exception> Failed;

        /// Queue of messages waiting to be sent.
        private BlockingCollection<QueueItem> outgoingMessageQueue = new BlockingCollection<QueueItem>();

        public static StringBuilder GenerateSpeechClientQuery(SpeechTranslateClientOptions options)
        {
            StringBuilder query = new StringBuilder();
            query.AppendFormat("from={0}&to={1}", options.TranslateFrom, options.TranslateTo);
            if (!String.IsNullOrWhiteSpace(options.Features))
            {
                query.AppendFormat("&features={0}", options.Features);
            }
            if (!String.IsNullOrWhiteSpace(options.Voice))
            {
                query.AppendFormat("&voice={0}", options.Voice);
            }

            if (!String.IsNullOrWhiteSpace(options.Profanity))
            {
                query.AppendFormat("&profanity={0}", options.Profanity);
            }

            if (!String.IsNullOrWhiteSpace(options.ProfanityAction))
            {
                query.AppendFormat("&profanityaction={0}", options.ProfanityAction);
            }

            if (!String.IsNullOrWhiteSpace(options.ApiVersion))
            {
                query.AppendFormat("&api-version={0}", options.ApiVersion);
            }

            if (!String.IsNullOrWhiteSpace(options.ProfanityMarker))
            {
                query.AppendFormat("&profanitymarker={0}", options.ProfanityMarker);
            }

            var flightParam = SpeechClient.SetFlightParam(options.UseExperimentalLanguages, options.UseAppLanguages);

            if (!String.IsNullOrEmpty(flightParam))
            {
                query.Append(flightParam);
            }

            if (string.IsNullOrEmpty(options.ClientTraceId))
            {
                options.ClientTraceId = Guid.NewGuid().ToString();
            }
            query.AppendFormat("&x-clientTraceId={0}", options.ClientTraceId);


            if (!String.IsNullOrWhiteSpace(options.AccessToken))
            {
                //url encode the token if sent as query string parameter
                query.AppendFormat("&access_token={0}", HttpUtility.UrlEncode(options.AccessToken));
            }

            return query;
        }

        public SpeechClient(SpeechTranslateClientOptions options, CancellationToken cancellationToken)
        {
            this.Init(options, cancellationToken);
            StringBuilder query = GenerateSpeechClientQuery(options);
            this.clientWsUri = new Uri(string.Format("{0}://{1}/{2}?{3}", this.options.IsSecure ? "wss": "ws", this.Hostname, options.Path, query.ToString()));
            this.SetHMACSignature();
        }

        public SpeechClient(SpeechDetectAndTranslateClientOptions options, CancellationToken cancellationToken)
        {
            this.Init(options, cancellationToken);
            StringBuilder query = new StringBuilder();
            query.AppendFormat("languages={0}", string.Join(",", options.Languages).Replace(" ", ""));
            if ((options.Voices != null) && (options.Voices.Length > 0))
            {
                query.AppendFormat("&voices={0}", string.Join(",", options.Voices).Replace(" ", ""));
            }
            if (!String.IsNullOrWhiteSpace(options.Features))
            {
                query.AppendFormat("&features={0}", options.Features);
            }
            if (!String.IsNullOrWhiteSpace(options.Profanity))
            {
                query.AppendFormat("&profanity={0}", options.Profanity);
            }
            this.clientWsUri = new Uri(string.Format("{0}://{1}/api/speech/detect-and-translate?{2}", this.options.IsSecure ? "wss" : "ws", this.Hostname, query.ToString()));
            this.SetHMACSignature();
        }

        private void Init(SpeechClientOptions options, CancellationToken cancellationToken)
        {
            if (options == null) throw new ArgumentNullException("options");
            if (cancellationToken == null) throw new ArgumentNullException("cancellationToken");

            this.options = options;
            this.cancellationToken = cancellationToken;
            this.webSocketclient = new ClientWebSocket();
            webSocketclient.Options.SetRequestHeader("X-ClientAppId", this.options.ClientAppId.ToString());
            
            if (!string.IsNullOrWhiteSpace(this.options.AuthHeaderKey))
            {
                webSocketclient.Options.SetRequestHeader(this.options.AuthHeaderKey, this.options.AuthHeaderValue);
            }
            
            if (!string.IsNullOrWhiteSpace(this.options.CorrelationId))
            {
                webSocketclient.Options.SetRequestHeader("X-CorrelationId", this.options.CorrelationId);
                // Value of X-CorrelationId is obfuscated in server logs. For test traffic served by this client, 
                // add the CorrelationId to a custom header in order to surface the ID in the logs. 
                webSocketclient.Options.SetRequestHeader("X-MT-TestCorrelationId", this.options.CorrelationId);
            }

            if (!string.IsNullOrWhiteSpace(this.options.OsPlatform))
            {
                webSocketclient.Options.SetRequestHeader("X-OsPlatform", this.options.OsPlatform);

            }
            if (!string.IsNullOrWhiteSpace(this.options.UserId))
            {
                webSocketclient.Options.SetRequestHeader("X-UserId", this.options.UserId);
            }

            if (!string.IsNullOrWhiteSpace(this.options.ScenarioId))
            {
                webSocketclient.Options.SetRequestHeader("X-ScenarioId", this.options.ScenarioId);
            }
        }

        /// <summary>
        /// Computes the HMAC signature for the given URL, app name and optional app key.
        /// </summary>
        /// <param name="requestUrl">URL of the request.</param>
        /// <param name="appName">HMAC app name.</param>
        /// <param name="appKey">HMAC app key. If omitted, the app name is used to lookup an existing key.</param>
        /// <returns>HMAC signature to send in X-MT-Sigature header.</returns>
        public static string GetHmacSignature(Uri requestUrl, string appName, string appKey = "")
        {
            if (requestUrl == null)
            {
                throw new ArgumentNullException(nameof(requestUrl));
            }
            if (String.IsNullOrEmpty(appName))
            {
                throw new ArgumentException(nameof(appName));
            }
            HMACSHA256 hmacKey;
            if (String.IsNullOrWhiteSpace(appKey))
            {
                throw new ArgumentException($"HMAC key not found for appName={appName}");
            }
            else
            {
                hmacKey = new HMACSHA256(Convert.FromBase64String(appKey));
            }

            var urlString = HttpUtility.UrlEncode(requestUrl.Host + requestUrl.PathAndQuery);
            var timeString = DateTime.UtcNow.ToString("r");
            var nonce = Guid.NewGuid().ToString("N");
            var signatureRawData = $"{appName}{urlString}{timeString}{nonce}".ToLower();
            var signature = Encoding.UTF8.GetBytes(signatureRawData);
            var hmacSignature = hmacKey.ComputeHash(signature);
            var hmacSignatureString = Convert.ToBase64String(hmacSignature);
            
            return $"{appName}::{hmacSignatureString}::{timeString}::{nonce}";
        }

        private void SetHMACSignature()
        {
            var appName = this.options.ADMClientId;
            if (!String.IsNullOrWhiteSpace(appName))
            {
                var signature = GetHmacSignature(this.clientWsUri, appName, options.HMACKey);
                webSocketclient.Options.SetRequestHeader("X-MT-Signature", signature);
            }
        }

        public string Hostname { get { return this.options.Hostname; } }

        public Uri ClientWsUri { get { return this.clientWsUri; } }

        public string RequestId { get { return this.options.ClientTraceId; } }

        public async Task Connect()
        {
            //validate the certificate for ssl requests
            if (this.options.IsSecure)
            {
                ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(HttpsCertificateValidator.ValidateServerCertificate);
            }

            await webSocketclient.ConnectAsync(this.clientWsUri, this.cancellationToken);
            // Start receive and send loops
            var receiveTask = Task.Run(() => this.StartReceiving())
                .ContinueWith((t) => ReportError(t))
                .ConfigureAwait(false);
            var sendTask = Task.Run(() => this.StartSending())
                .ContinueWith((t) => ReportError(t))
                .ConfigureAwait(false);
        }

        public bool IsConnected()
        {
            WebSocketState wsState = WebSocketState.None;
            try
            {
                wsState = this.webSocketclient.State;
            }
            catch (ObjectDisposedException)
            {
                wsState = WebSocketState.None;
            }
            return ((this.cancellationToken.IsCancellationRequested == false)
                 && ((wsState == WebSocketState.Open) || (wsState == WebSocketState.CloseReceived)));
        }

        public async Task Disconnect()
        {
            if (this.IsConnected())
            {
                try
                {
                    await this.webSocketclient.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, this.cancellationToken);
                }
                finally
                {
                    if (this.Disconnected != null) this.Disconnected(this, EventArgs.Empty);
                }
            }
        }

        public void SendBinaryMessage(ArraySegment<byte> content)
        {
            SendMessage(WebSocketMessageType.Binary, content);
        }

        public void SendTextMessage(string text)
        {
            SendMessage(WebSocketMessageType.Text, new ArraySegment<byte>(Encoding.UTF8.GetBytes(text)));
        }

        private void SendMessage(WebSocketMessageType messageType, ArraySegment<byte> content)
        {
            var msg = new QueueItem(messageType, content);
            this.outgoingMessageQueue.Add(msg);
        }

        /// Starts a loop to send websocket messages queued in the outgoing message queue.
        private async Task StartSending()
        {
            while (this.IsConnected())
            {
                QueueItem item = null;
                if (this.outgoingMessageQueue.TryTake(out item, 100))
                {
                    try
                    {
                        await this.webSocketclient.SendAsync(item.Content, item.OpCode, true, this.cancellationToken);
                        item.CompletionSource.TrySetResult(true);
                    }
                    catch (OperationCanceledException)
                    {
                        item.CompletionSource.TrySetCanceled();
                    }
                    catch (ObjectDisposedException)
                    {
                        item.CompletionSource.TrySetCanceled();
                    }
                    catch (Exception ex)
                    {
                        item.CompletionSource.TrySetException(ex);
                        throw;
                    }
                }
            }
        }

        //Receive loop
        private async Task StartReceiving()
        {
            var buffer = new byte[ReceiveChunkSize];
            var arraySegmentBuffer = new ArraySegment<byte>(buffer);
            Task<WebSocketReceiveResult> receiveTask = null;
            bool disconnecting = false;
            while (this.IsConnected() && !disconnecting)
            {
                if (receiveTask == null)
                {
                    receiveTask = this.webSocketclient.ReceiveAsync(arraySegmentBuffer, this.cancellationToken);
                }
                if (receiveTask.Wait(100))
                {
                    WebSocketReceiveResult result = await receiveTask;
                    receiveTask = null;
                    EventHandler<ArraySegment<byte>> handler = null;
                    switch (result.MessageType)
                    {
                        case WebSocketMessageType.Close:
                            disconnecting = true;
                            await this.Disconnect();
                            break;
                        case WebSocketMessageType.Binary:
                            handler = result.EndOfMessage ? this.OnEndOfBinaryData : this.OnBinaryData;
                            break;
                        case WebSocketMessageType.Text:
                            handler = result.EndOfMessage ? this.OnEndOfTextData : this.OnTextData;
                            break;
                    }
                    if (handler != null)
                    {
                        var data = new byte[result.Count];
                        Array.Copy(buffer, data, result.Count);
                        handler(this, new ArraySegment<byte>(data));
                    }
                }
            }
        }

        public void Dispose()
        {
            if (this.webSocketclient != null)
            {
                webSocketclient.Dispose();
            }
        }

        public static string SetFlightParam(bool useExperimentalLanguages, bool useAppLanguages)
        {
            string flightParam = "";
            var flights = new List<string>();
            if (useExperimentalLanguages)
            {
                flights.Add("experimental");
            }

            if (useAppLanguages)
            {
                flights.Add("app");
            }

            if (flights.Count > 0)
            {
                flightParam = "&flight=" + String.Join(",", flights);
            }
            return flightParam;
        }

        private void ReportError(Task task)
        {
            if (task.IsFaulted)
            {
                if (this.Failed != null) Failed(this, task.Exception);
            }
        }
    }
}
