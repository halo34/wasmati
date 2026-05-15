(module
  (import "env" "gets" (func $gets (param i32) (result i32)))
  (memory 1)

  (func $vuln (export "vuln") (param $buf i32)
    ;; Vulnerable pattern: direct call to dangerous function gets.
    local.get $buf
    call $gets
    drop)
)
