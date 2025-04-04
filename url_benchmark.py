import timeit

from yarl import URL

MANY_HOSTS = [f"www.domain{i}.tld" for i in range(10000)]
MANY_URLS = [f"https://www.domain{i}.tld" for i in range(10000)]
BASE_URL = URL("http://www.domain.tld")
QUERY_URL = URL("http://www.domain.tld?query=1&query=2&query=3&query=4&query=5")
URL_WITH_PATH = URL("http://www.domain.tld/req")

print(
    "Build URL with host and path and port: {:.3f} sec".format(
        timeit.timeit(
            "URL.build(host='www.domain.tld', path='/req', port=1234)",
            globals={"URL": URL},
            number=100000,
        )
    )
)

print(
    "Build encoded URL with host and path and port: {:.3f} sec".format(
        timeit.timeit(
            "URL.build(host='www.domain.tld', path='/req', port=1234, encoded=True)",
            globals={"URL": URL},
            number=100000,
        )
    )
)

print(
    "Build URL with host: {:.3f} sec".format(
        timeit.timeit("URL.build(host='domain')", globals={"URL": URL}, number=100000)
    )
)

print(
    "Build URL with different hosts: {:.3f} sec".format(
        timeit.timeit(
            "for host in hosts: URL.build(host=host)",
            globals={"URL": URL, "hosts": MANY_HOSTS},
            number=10,
        )
    )
)

print(
    "Build URL with host and port: {:.3f} sec".format(
        timeit.timeit(
            "URL.build(host='www.domain.tld', port=1234)",
            globals={"URL": URL},
            number=100000,
        )
    )
)

print(
    "Make URL with host and path and port: {:.3f} sec".format(
        timeit.timeit(
            "URL('http://www.domain.tld:1234/req')", globals={"URL": URL}, number=100000
        )
    )
)

print(
    "Make encoded URL with host and path and port: {:.3f} sec".format(
        timeit.timeit(
            "URL('http://www.domain.tld:1234/req', encoded=True)",
            globals={"URL": URL},
            number=100000,
        )
    )
)

print(
    "Make URL with host and path: {:.3f} sec".format(
        timeit.timeit(
            "URL('http://www.domain.tld/req')", globals={"URL": URL}, number=100000
        )
    )
)

print(
    "Make URL with many hosts: {:.3f} sec".format(
        timeit.timeit(
            "for url in urls: URL(url)",
            globals={"URL": URL, "urls": MANY_URLS},
            number=10,
        )
    )
)


print(
    "Make URL with IPv4 Address and path and port: {:.3f} sec".format(
        timeit.timeit(
            "URL('http://127.0.0.1:1234/req')", globals={"URL": URL}, number=100000
        )
    )
)


print(
    "Make URL with IPv4 Address and path: {:.3f} sec".format(
        timeit.timeit(
            "URL('http://127.0.0.1/req')", globals={"URL": URL}, number=100000
        )
    )
)


print(
    "Make URL with IPv6 Address and path and port: {:.3f} sec".format(
        timeit.timeit(
            "URL('http://[::1]:1234/req')", globals={"URL": URL}, number=100000
        )
    )
)


print(
    "Make URL with IPv6 Address and path: {:.3f} sec".format(
        timeit.timeit("URL('http://[::1]/req')", globals={"URL": URL}, number=100000)
    )
)


print(
    "Make URL with query mapping: {:.3f} sec".format(
        timeit.timeit(
            "base_url.with_query("
            "{'a':'1','b':'2','c':'3','d':'4','e':'5'"
            ",'f':'6','g':'7','h':'8','i':'9','j':'10'}"
            ")",
            globals={"base_url": BASE_URL, "URL": URL},
            number=100000,
        )
    )
)


print(
    "Make URL with query sequence mapping: {:.3f} sec".format(
        timeit.timeit(
            "".join(
                [
                    "base_url.with_query({",
                    *[
                        f"'{i}':('1','2','3','4','5','6','7','8','9','10'),"
                        for i in range(10)
                    ],
                    "})",
                ]
            ),
            globals={"base_url": BASE_URL, "URL": URL},
            number=100000,
        )
    )
)


print(
    "Convert URL to string: {:.3f} sec".format(
        timeit.timeit(
            "str(base_url)",
            globals={"base_url": BASE_URL, "URL": URL},
            number=100000,
        )
    )
)


print(
    "Convert URL with path to string: {:.3f} sec".format(
        timeit.timeit(
            "str(url_with_path)",
            globals={"url_with_path": URL_WITH_PATH, "URL": URL},
            number=100000,
        )
    )
)


print(
    "Convert URL with query to string: {:.3f} sec".format(
        timeit.timeit(
            "str(query_url)",
            globals={"query_url": QUERY_URL, "URL": URL},
            number=100000,
        )
    )
)
