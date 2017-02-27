using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.MT.Api.TestUtils
{

    /// <summary>
    /// Defines the set of parameters available to configure the client.
    /// </summary>
    public abstract class SpeechClientOptions
    {
        public string Hostname { get; set; }
        public string AccessToken { get; set; }
        public string AuthHeaderKey { get; set; }
        public string AuthHeaderValue { get; set; }
        public string Features { get; set; }
        public string Profanity { get; set; }
        public string ProfanityAction { get; set; }
        public string ProfanityMarker { get; set; }
        public Guid ClientAppId { get; set; }
        public string CorrelationId { get; set; }
        public string ADMClientId { get; set; }

        public string ClientTraceId { get; set; }
        /// <summary>
        /// Indicates if the connection is through secured layer (SSL)
        /// </summary>
        public bool IsSecure { get; set; }
        public bool UseExperimentalLanguages { get; set; }
        public bool UseAppLanguages { get; set; }
        public string ScenarioId { get; set; }
        public string UserId { get; set; }
        public string HMACKey { get; set; }
        public string ApiVersion { get; set; }

        public string OsPlatform { get; set; }

    }

    /// <summary>
    /// Defines the set of parameters to configure the client in order to use Translate endpoint.
    /// </summary>
    public class SpeechTranslateClientOptions : SpeechClientOptions
    {
        public SpeechTranslateClientOptions()
        {
            Path = "api/speech/translate";
        }

        public string TranslateFrom { get; set; }
        public string TranslateTo { get; set; }
        public string Voice { get; set; }
        public string Path { get; set; }
    }

    /// <summary>
    /// Defines the set of parameters to configure the client in order to use DetectAndTranslate endpoint.
    /// </summary>
    public class SpeechDetectAndTranslateClientOptions : SpeechClientOptions
    {
        /// Array of selected languages for DetectAndTranslate.
        public string[] Languages { get; set; }
        /// Array of selected voices for DetectAndTranslate.
        public string[] Voices { get; set; }
    }
}
