package com.javadeobfuscator.deobfuscator.transformers.special;

import java.util.List;

import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.exceptions.WrongTransformerException;
import com.javadeobfuscator.deobfuscator.transformers.Transformer;
import org.apache.commons.lang3.StringUtils;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

public class CaesiumTransformer extends Transformer<TransformerConfig> {

    @Override
    public boolean transform() throws Throwable, WrongTransformerException {
        boolean edit = cleanAnnotations();
        
        return edit;
    }

    private boolean cleanAnnotations() {
        boolean edit = false;
        for (ClassNode classNode : classNodes()) {
            edit = cleanAnnotations(classNode.visibleAnnotations) | edit;
            edit = cleanAnnotations(classNode.invisibleAnnotations) | edit;
            edit = cleanAnnotations(classNode.visibleTypeAnnotations) | edit;
            edit = cleanAnnotations(classNode.invisibleTypeAnnotations) | edit;
            for (MethodNode methodNode : classNode.methods) {
                edit = cleanAnnotations(methodNode.visibleAnnotations) | edit;
                edit = cleanAnnotations(methodNode.invisibleAnnotations) | edit;
                edit = cleanAnnotations(methodNode.visibleTypeAnnotations) | edit;
                edit = cleanAnnotations(methodNode.invisibleTypeAnnotations) | edit;
                edit = cleanAnnotations(methodNode.visibleLocalVariableAnnotations) | edit;
                edit = cleanAnnotations(methodNode.invisibleLocalVariableAnnotations) | edit;
                edit = cleanAnnotations(methodNode.visibleParameterAnnotations) | edit;
                edit = cleanAnnotations(methodNode.invisibleParameterAnnotations) | edit;
            }
            for (FieldNode fieldNode : classNode.fields) {
                edit = cleanAnnotations(fieldNode.visibleAnnotations) | edit;
                edit = cleanAnnotations(fieldNode.invisibleAnnotations) | edit;
                edit = cleanAnnotations(fieldNode.visibleTypeAnnotations) | edit;
                edit = cleanAnnotations(fieldNode.invisibleTypeAnnotations) | edit;
            }
        }
        return edit;
    }

    private static boolean cleanAnnotations(List<? extends AnnotationNode> list) {
        if (list == null) {
            return false;
        }
        return list.removeIf(next -> StringUtils.containsOnly(next.desc, "\n"));
    }

    private static boolean cleanAnnotations(List<? extends AnnotationNode>[] lists) {
        if (lists == null) {
            return false;
        }
        boolean edit = false;
        for (List<? extends AnnotationNode> list : lists) {
            edit = cleanAnnotations(list) | edit;
        }
        return true;
    }
}
