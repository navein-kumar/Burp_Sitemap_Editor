# Burp Suite Sitemap Import/Export Extension

A Burp Suite extension for importing and exporting Site Map with bulk find/replace capabilities. Perfect for changing target hosts, modifying headers, or updating tokens across multiple requests.

## Features

- **Import XML to Site Map** - Load Burp-exported XML files back into Site Map
- **Export Site Map to XML** - Save current Site Map to XML file
- **Bulk Find/Replace** - Modify requests during import (host, headers, tokens, etc.)
- **Side-by-Side Preview** - View original vs modified requests before importing
- **Preset Rules** - Quick buttons for common operations
- **Regex Support** - Advanced pattern matching

## Installation

1. Download `sitemap_importer_v2.py`
2. In Burp Suite: **Extensions > Add**
3. Extension type: **Python**
4. Select the `.py` file
5. Click **Next**

**Requirement:** Jython standalone JAR configured in Burp Suite

## Usage

### Tab 1: Quick Presets

Common replacement rules:

| Preset | Description |
|--------|-------------|
| Host Replacement | Replace domain in URL + Host header |
| Authorization Token | Replace Bearer tokens |
| Remove Header | Strip specific headers |
| HTTP/2 -> HTTP/1.1 | Convert protocol version |
| Strip Cookies | Remove Cookie headers |
| Normalize User-Agent | Standardize UA string |

### Tab 2: Custom Rules

Add custom find/replace rules:
- **Find:** Text or regex pattern
- **Replace:** Replacement text (empty = remove)
- **Regex:** Enable for pattern matching
- **Case Sensitive:** Match case exactly

### Tab 3: Import / Export

**Import Flow:**
1. Click **Select XML File**
2. Preview shows original vs modified (use Previous/Next to browse)
3. Click **Refresh Preview** after adding new rules
4. Click **IMPORT TO SITE MAP**

**Export Flow:**
1. Check **In Scope Only** if needed
2. Click **Export Site Map to XML**

## Common Use Cases

### Change Target Host (Bypass WAF)

```
Find: api.example.com
Replace: api.internal.com
```

This replaces the host everywhere - URL, Host header, Referer, etc.

### Update Authorization Token

Use preset or add rule:
```
Find: Authorization: .*
Replace: Authorization: Bearer eyJ...newtoken...
Regex: Yes
```

### Remove Tracking Headers

```
Find: X-Request-ID:.*\r\n
Replace: (empty)
Regex: Yes
```

## How Rules Work

- Rules apply to: URL, Request headers, Request body, Response
- All requests are imported (matched or not)
- Matched requests are modified
- Unmatched requests import unchanged
- Rules execute in order (top to bottom)

## File Format

Uses standard Burp XML format with base64-encoded requests/responses:

```xml
<items burpVersion="2025.x.x" exportTime="...">
  <item>
    <url>https://example.com/api</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <request base64="true">...</request>
    <response base64="true">...</response>
  </item>
</items>
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Non-ASCII error | Fixed in v2 - uses ISO-8859-1 encoding |
| Rules not applying | Click **Refresh Preview** to verify |
| Import errors | Check Log panel for details |
| Extension won't load | Verify Jython JAR is configured |

## License

MIT License - Free to use and modify

## Author

Created for penetration testing workflows where target host changes or bulk request modifications are needed.
