/*
 *  Entry point of the WASM bundle.
 *
 *  The real API is the exported 'process'/'json_free' pair from the uapki
 *  library (see uapki/include/uapki-export.h). main() is intentionally empty:
 *  the module is driven from JavaScript, see demo/index.html.
 */

int main (void)
{
    return 0;
}
