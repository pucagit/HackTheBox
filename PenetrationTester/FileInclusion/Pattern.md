# Examples of Vulnerable Code
## PHP

```
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

## NodeJS

```
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

```
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});

```

## Java

```
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

```
<c:import url= "<%= request.getParameter('language') %>"/>
```

## .NET

```
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

```
@Html.Partial(HttpContext.Request.Query['language'])
```

```
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Function</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Read Content</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Execute</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Remote URL</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">PHP</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include()</code>/<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include_once()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">require()</code>/<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">require_once()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">file_get_contents()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">fopen()</code>/<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">file()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">NodeJS</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">fs.readFile()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">fs.sendFile()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">res.render()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">Java</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">import</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">.NET</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">@Html.Partial()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">@Html.RemotePartial()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Response.WriteFile()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr></tbody></table>