<?php
// Directory guard (Exercise 01): if a web server is ever pointed at this folder,
// it gets an empty 403 instead of a directory listing. Intentionally reveals nothing.
http_response_code(403);
exit;
