package lib;
// The injected sink boundary: a vulnerable library's deserializer, behind an interface.
public interface IStore { Object load(String data); }
