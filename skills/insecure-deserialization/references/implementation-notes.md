# Implementation notes

Review Java ObjectInputStream/XStream/Jackson typing, PHP unserialize/PHAR magic methods, .NET BinaryFormatter/LosFormatter, Python pickle/yaml unsafe loaders, Ruby Marshal, and framework session formats. Signed serialization still exposes risk if keys leak or trusted producers can be influenced; encryption alone does not make object construction safe.
