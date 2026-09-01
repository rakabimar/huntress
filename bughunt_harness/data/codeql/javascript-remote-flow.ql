/** @name Remote input to request/process sink @kind path-problem @problem.severity warning @precision medium @id bughunt/js-remote-flow */
import javascript
import semmle.javascript.security.dataflow.RemoteFlowSource
import DataFlow::PathGraph

class DangerousSink extends DataFlow::Node {
  DangerousSink() {
    exists(CallExpr call |
      this = call.getArgument(0) and
      (call.getCalleeName() = "fetch" or call.getCalleeName() = "exec" or call.getCalleeName() = "readFile")
    )
  }
}

module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof DangerousSink }
}

module Flow = TaintTracking::Global<FlowConfig>;
from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches this dangerous sink."
