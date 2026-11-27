"""Built-in analyzer plugins.

Importing this package registers every analyzer via its @register decorator.
Add a new source by dropping a module here and listing it below.
"""
from . import (  # noqa: F401
    breaches,
    crtsh,
    dns,
    email,
    emailrep,
    github_emails,
    holehe_email,
    http_probe,
    hunter,
    ip_geo,
    jobs,
    phone,
    profile,
    rdap,
    reddit,
    search_dorks,
    sec_edgar,
    sherlock,
    shodan_internetdb,
    username,
)
