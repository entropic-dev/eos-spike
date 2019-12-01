# object-store

The goals of this module are as follows:

- Storing objects in a content addressable form
- Allowing the preferred content address hash to be "upgraded" (e.g.: sha256 -> sha512)
- Safely allowing multiple concurrent writers
- Allowing fast object presence checks
- Allowing use in JS (via WASM)
- Allowing fast object reads
- Iterating over the objects contained in the store
- Consistency:
    - reads can be inconsistent (it's okay to read something, decide to fetch it, and then come back to find out it's already there)
    - writes must be atomic (content cannot be put in place until it's fully baked)
- Optimize for read performance over write performance
    - writes happen once per unique content encounter
    - reads happen multiple times every time the node program executes

Prior art:

- [Package Distribution](https://gist.github.com/jcoglan/64cf9d3f9a4e25092ac132bd72b63491) by jcoglan
- [Package Syncing](https://gist.github.com/chrisdickinson/579aeccf0b304aac2b8891e36849c98e) by chrisdickinson

---

# what types of objects do we have?

## Immutable, content-addressable:

- **Blobs:** raw content
- **Versions:** versions of a package, storing maps to blobs
    - package name
    - version name
    - dependencies
    - creation date
    - files (a map of files at versions)
- **Signatures:** signatures over a version
    - version
    - date
    - signature
    - origin? publickey?

## Mutable:

- Toplevel packages
    - List of available package-versions
- Per-registry representations of package-versions (probably not stored here)
    - These contain rendered readmes/file contents
