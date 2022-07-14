/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

goog.require('punycode');
goog.require('goog.crypt');
goog.require('goog.crypt.Sha256');
goog.require('goog.crypt.baseN');
goog.require('goog.i18n.bidi');

/**
 * Constructs a human readable cache subdomain encoded proxy domain using the
 * following algorithm:
 *   Convert domain from punycode to utf-8 (if applicable)
 *   Replace every '-' with '--'
 *   Replace every '.' with '-'
 *   Convert back to punycode (if applicable)
 *
 * @param {string} domain The publisher domain
 * @return {string} The encoded domain
 * @private
 */
function constructHumanReadableCurlsProxyDomain_(domain) {
  domain = punycode.toUnicode(domain.toLowerCase());
  domain = domain.split('-').join('--');
  domain = domain.split('.').join('-');
  return punycode.toAscii(domain);
}

/**
 * Constructs a cache subdomain following instructions at
 * https://developers.google.com/search/docs/advanced/experience/signed-exchange#debug-the-google-sxg-cache
 * @param {string} domain The publisher domain
 * @return {string} The encoded domain
 */
 function constructPerPublisherProxyAuthority(domain) {
  var curlsEncoding = isEligibleForHumanReadableProxyEncoding_(domain) ?
      constructHumanReadableCurlsProxyDomain_(domain) :
      constructFallbackCurlsProxyDomain_(domain);
  const MAX_DOMAIN_LABEL_LENGTH = 63;
  // The length of the encoded string cannot exceed 63 characters
  if (curlsEncoding.length > MAX_DOMAIN_LABEL_LENGTH) {
    curlsEncoding = constructFallbackCurlsProxyDomain_(domain);
  }
  // Check for violations of RFC 5891
  // https://tools.ietf.org/html/rfc5891#section-4.2.3.1
  // Punycode library will generate such URLs even though they are invalid.
  if (this.hasInvalidHyphen34_(curlsEncoding)) {
    curlsEncoding = constructCurlsProxyDomainForHyphen34_(curlsEncoding);
  }
  return curlsEncoding;
}

/**
 * Determines whether the given domain can be validly encoded into a human
 * readable curls encoded proxy domain.  A domain is eligible as long as:
 *   It does not have hyphens in positions 3&4.
 *   It does not exceed 63 characters
 *   It does not contain a mix of right-to-left and left-to-right characters
 *   It contains a dot character
 *
 * @param {string} domain The domain to validate
 * @return {boolean}
 * @private
 */
function isEligibleForHumanReadableProxyEncoding_(domain) {
  if (hasInvalidHyphen34_(domain)) {
    return false;
  }
  var unicode = punycode.toUnicode(domain);
  const MAX_DOMAIN_LABEL_LENGTH = 63;
  return domain.length <= MAX_DOMAIN_LABEL_LENGTH &&
      !(goog.i18n.bidi.hasAnyLtr(unicode) &&
        goog.i18n.bidi.hasAnyRtl(unicode)) &&
      domain.indexOf('.') != -1;
}

/**
 * Determines if a domain or curls encoded proxy domain is allowed to have a
 * hyphen in positions 3&4.
 *
 * @param {string} domainOrCurls A publisher domain or curls encoded proxy
 *   domain
 * @return {boolean}
 * @private
 */
function hasInvalidHyphen34_(domainOrCurls) {
  return domainOrCurls.slice(2, 4) == '--' &&
      domainOrCurls.slice(0, 2) != 'xn';
}

/**
 * Constructs a fallback curls encoded proxy domain by taking the SHA256 of
 * the domain and base32 encoding it.
 *
 * @param {string} domain The publisher domain
 * @return {string} The curls encoded domain
 * @private
 */
function constructFallbackCurlsProxyDomain_(domain) {
  var sha256 = new goog.crypt.Sha256();
  sha256.update(domain, domain.length);
  var hexString = goog.crypt.byteArrayToHex(sha256.digest());
  return this.base32Encode_(hexString);
}

/**
 * Constructs a human readable curls for when the constructed curls has a
 * hyphen in position 3&4.
 *
 * @param {string} curlsEncoding The curls encoded domain with hyphen in
 *   position 3&4
 * @return {string} The transformed curls encoded domain
 * @private
 */
function constructCurlsProxyDomainForHyphen34_(curlsEncoding) {
  var prefix = '0-';
  return prefix.concat(curlsEncoding, '-0');
}

/**
 * Encodes a hex string in base 32 according to specs in RFC 4648 section 6.
 * Unfortunately, our only conversion tool is baseN.recodeString which
 * converts a string from base16 to base32 numerically, trimming off leading
 * 0's in the process. We use baseN to perform a base32 encoding as follows:
 *   Start with 256 bit sha encoded as a 64 char hex string
 *   Append 24 bits (6 hex chars) for a total of 280, exactly 7 40-bit chunks
 *   Prepend a 40-bit block of 1's (10 'f' chars) so that basen doesn't trim
 *     the beginning when converting
 *   Call basen
 *   Trim the first 8 chars (the 40 1's)
 *   Trim the last 4 chars
 *
 * @param {string} hexString The hex string
 * @return {string} The base32 encoded string
 * @private
 */
function base32Encode_(hexString) {
  var initialPadding = 'ffffffffff';
  var finalPadding = '000000';
  var paddedString = initialPadding + hexString + finalPadding;
  var base16 = goog.crypt.baseN.BASE_LOWERCASE_HEXADECIMAL;
  // We use the base32 character encoding defined here:
  // https://tools.ietf.org/html/rfc4648
  var base32 = 'abcdefghijklmnopqrstuvwxyz234567';
  var recodedString =
      goog.crypt.baseN.recodeString(paddedString, base16, base32);

  var bitsPerHexChar = 4;
  var bitsPerBase32Char = 5;
  var numInitialPaddingChars =
      initialPadding.length * bitsPerHexChar / bitsPerBase32Char;
  var numHexStringChars =
      Math.ceil(hexString.length * bitsPerHexChar / bitsPerBase32Char);
  return recodedString.substr(numInitialPaddingChars, numHexStringChars);
}

function getCertUrl(result) {
  const resultArray = result.split(';');
  if (resultArray.length >= 3) {
    for (let i = 0; i < resultArray.length; i++) {
      var pair = resultArray[2].split('=');
      if (pair[0] != 'cert-url') {
        continue;
      }
      if (pair.length >= 2) {
        return pair[1];
      }
    }
  }
  return null;
}

async function setCertDisplayFields(result) {
  const contentType = result.headers.get('Content-Type');
  const warning = result.headers.get('Warning');
  const location = result.headers.get('Location');

  var correctContentType = contentType == 'application/cert-chain+cbor';
  document.getElementById('certurl').textContent = result.url;
  document.getElementById('certcontenttype').textContent = contentType;
  document.getElementById('certwarning').textContent = warning;
  document.getElementById('certlocation').textContent = location;

  let buffer = await result.arrayBuffer();
  var enc = new TextDecoder("utf-8");
  var s = enc.decode(buffer);
  if (warning === null && location !== null) {
    document.getElementById('certimg').innerHTML = "⌛";
  } else if (correctContentType) {
      document.getElementById('certimg').innerHTML = "✅";
  } else {
      document.getElementById('certimg').innerHTML = "❌";
  }
}

async function setDisplayFields(result, urlFieldId, contentTypeFieldId,
                                imgFieldId) {
  const contentType = result.headers.get('Content-Type');
  const warning = result.headers.get('Warning');
  const location = result.headers.get('Location');

  var correctContentType = contentType == 'application/signed-exchange;v=b3';
  document.getElementById(urlFieldId).textContent = result.url;
  document.getElementById(contentTypeFieldId).textContent = contentType;
  if (urlFieldId === "cacheurl") {
    document.getElementById('cachewarning').textContent = warning;
    document.getElementById('cachelocation').textContent = location;
  }

  let buffer = await result.arrayBuffer();
  var enc = new TextDecoder("utf-8");
  var s = enc.decode(buffer);
  if (warning === null && location !== null) {
    document.getElementById(imgFieldId).innerHTML = "⌛";
  } else if (correctContentType && s.startsWith('sxg1-b3\0')) {
      document.getElementById(imgFieldId).innerHTML = "✅";
  } else {
      document.getElementById(imgFieldId).innerHTML = "❌";
      if (urlFieldId === "url") {
        document.getElementById("extra-sxg-info").style.display = "none";
      }
  }
  let certUrl = getCertUrl(s);

  if (certUrl) {
    let certResult = await fetch(certUrl.slice(1, -1), {
      method: "GET",
      headers: { 
        "Accept": "application/cert-chain+cbor",
      }});

    setCertDisplayFields(certResult);
  }
}

// Update the relevant fields with the new data.
function setDOMInfo(url) {
  fetch(url, {
    method: "GET",
    headers: {
      "Accept": "*/*;q=0.8,application/signed-exchange;v=b3",
    }
  }).then(result => {
    setDisplayFields(result, 'url', 'contenttype', 'originimg');
  })
  .catch((error) => {
    console.log(error)
  });

  const urlObject = new URL(url);
  cacheUrl = 'https://' 
    + constructPerPublisherProxyAuthority(urlObject.host) 
    + '.webpkgcache.com/doc/-/s/'
    + urlObject.host
    + urlObject.pathname;

  const params = urlObject.searchParams.toString();
  if (params != "") {
    cacheUrl = cacheUrl + '?' + params;
  }

  fetch(cacheUrl, {
    method: "GET",
    headers: {
      "Accept": "application/signed-exchange;v=b3",
    }
  }).then(result => {
    setDisplayFields(result, 'cacheurl', 'cachecontenttype', 'cacheimg');
  })
  .catch((error) => {
    console.log(error)
  });
};

window.addEventListener('DOMContentLoaded', () => {
  // Query for the active tab
  chrome.tabs.query({
    active: true,
    currentWindow: true
  }, tabs => {
    setDOMInfo(tabs[0].url);
  });
});

