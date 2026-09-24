// Renders the Agent B app icon (dark rounded square + orange "B")
// to a 1024x1024 PNG, matching the harness brand mark in static/styles.css.
// Uses CoreGraphics/CoreText/ImageIO so it renders headless (no WindowServer).
//   clang -fobjc-arc -framework Foundation -framework CoreGraphics \
//         -framework CoreText -framework ImageIO make-icon.m -o make-icon
//   ./make-icon out.png
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreText/CoreText.h>
#import <ImageIO/ImageIO.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *outPath = (argc > 1) ? [NSString stringWithUTF8String:argv[1]] : @"icon-1024.png";
        const CGFloat S = (argc > 2) ? atof(argv[2]) : 1024.0;

        CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        CGContextRef ctx = CGBitmapContextCreate(NULL, (size_t)S, (size_t)S, 8, 0, cs,
            kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
        if (!ctx) { fprintf(stderr, "no context\n"); return 1; }

        // Rounded-square plate with standard macOS icon padding.
        CGFloat margin = S * 0.086;
        CGRect plate = CGRectMake(margin, margin, S - 2 * margin, S - 2 * margin);
        CGFloat radius = plate.size.width * 0.2237; // macOS "squircle" corner ratio
        CGPathRef platePath = CGPathCreateWithRoundedRect(plate, radius, radius, NULL);

        // Soft drop shadow under the plate.
        CGContextSaveGState(ctx);
        CGContextSetShadowWithColor(ctx, CGSizeMake(0, -S * 0.012), S * 0.03,
            CGColorCreateGenericRGB(0, 0, 0, 0.28));
        CGContextAddPath(ctx, platePath);
        CGContextSetRGBFillColor(ctx, 0, 0, 0, 1);
        CGContextFillPath(ctx);
        CGContextRestoreGState(ctx);

        // Charcoal gradient plate.
        CGContextSaveGState(ctx);
        CGContextAddPath(ctx, platePath);
        CGContextClip(ctx);
        CGFloat comps[8] = {
            0x29/255.0, 0x29/255.0, 0x29/255.0, 1.0,   // charcoal
            0x10/255.0, 0x10/255.0, 0x10/255.0, 1.0,   // near black
        };
        CGFloat locs[2] = {0.0, 1.0};
        CGGradientRef grad = CGGradientCreateWithColorComponents(cs, comps, locs, 2);
        // angle ~ -55deg from top-left toward bottom-right
        CGPoint start = CGPointMake(plate.origin.x, CGRectGetMaxY(plate));
        CGPoint end   = CGPointMake(CGRectGetMaxX(plate), plate.origin.y);
        CGContextDrawLinearGradient(ctx, grad, start, end, 0);
        CGContextRestoreGState(ctx);

        // Bold orange B, centered.
        CGFloat fontSize = S * 0.6;
        CTFontRef font = CTFontCreateWithName(CFSTR("HelveticaNeue-Bold"), fontSize, NULL);
        CGColorRef ink = CGColorCreateGenericRGB(0xff/255.0, 0x80/255.0, 0x35/255.0, 1.0);
        CFStringRef keys[]   = { kCTFontAttributeName, kCTForegroundColorAttributeName };
        CFTypeRef   values[] = { font, ink };
        CFDictionaryRef attrs = CFDictionaryCreate(NULL, (const void **)keys, (const void **)values, 2,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFAttributedStringRef attr = CFAttributedStringCreate(NULL, CFSTR("B"), attrs);
        CTLineRef line = CTLineCreateWithAttributedString(attr);
        CGRect glyphRect = CTLineGetBoundsWithOptions(line, kCTLineBoundsUseGlyphPathBounds);
        CGFloat tx = (S - glyphRect.size.width) / 2.0 - glyphRect.origin.x;
        CGFloat ty = (S - glyphRect.size.height) / 2.0 - glyphRect.origin.y;
        CGContextSetTextPosition(ctx, tx, ty);
        CTLineDraw(line, ctx);

        CGImageRef image = CGBitmapContextCreateImage(ctx);
        CFURLRef url = (__bridge CFURLRef)[NSURL fileURLWithPath:outPath];
        CGImageDestinationRef dest = CGImageDestinationCreateWithURL(url, CFSTR("public.png"), 1, NULL);
        if (!dest) { fprintf(stderr, "no destination\n"); return 1; }
        CGImageDestinationAddImage(dest, image, NULL);
        if (!CGImageDestinationFinalize(dest)) { fprintf(stderr, "failed to write %s\n", outPath.UTF8String); return 1; }
        fprintf(stdout, "wrote %s\n", outPath.UTF8String);
    }
    return 0;
}
