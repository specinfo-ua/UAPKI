//  Entropy source for uapkic (see uapkic/src/entropy.c, __EMSCRIPTEN__ branch):
//  os_prng() pulls single random bytes via Module.getRandomValue().
//  A pooled Web Crypto implementation keeps that reasonably fast.
Module['getRandomValue'] = (function () {
    const pool = new Uint8Array(4096);
    let pos = pool.length;
    return function () {
        if (pos >= pool.length) {
            crypto.getRandomValues(pool);
            pos = 0;
        }
        return pool[pos++];
    };
})();
