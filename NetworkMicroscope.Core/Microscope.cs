namespace NetworkMicroscope.Core;

public class Microscope
{
    public string Target { get; }

    public Microscope(string target)
    {
        Target = target;
    }

    public string GetHello()
    {
        return $"Hello from NetworkMicroscope Core! Targeting: {Target}";
    }
}