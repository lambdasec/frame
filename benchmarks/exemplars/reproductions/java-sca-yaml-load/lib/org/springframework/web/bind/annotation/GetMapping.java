package org.springframework.web.bind.annotation;

import java.lang.annotation.*;

// Stand-in for Spring's annotation, so the case compiles with javac alone.
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
public @interface GetMapping { String[] value() default {}; }
